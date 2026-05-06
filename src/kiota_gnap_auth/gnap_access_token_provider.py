"""
GNAP Access Token Provider for Kiota

Implements Kiota's AccessTokenProvider pattern to orchestrate the
GNAP grant lifecycle: check cache → rotate → request grant → store token.

Features:
- Cache-first token retrieval with TTL-aware storage
- Proactive token refresh within grace period
- Token rotation via management URI with fallback
- Concurrent acquisition guard (prevents duplicate grants)
- Continuation polling with wait interval support
- Typed event emission for lifecycle observability

@see https://www.rfc-editor.org/rfc/rfc9635#section-2
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from .errors import GnapInteractionRequiredError
from .events import GnapEventEmitter
from .gnap_grant_manager import GnapGrantManager
from .types import (
    AccessRight,
    ContinuationInfo,
    GrantResponse,
    InteractionConfig,
    TokenInfo,
)

# Grace period (seconds) before expiry to trigger proactive refresh
REFRESH_GRACE_S = 30

# Default maximum polling attempts for continuation
MAX_POLL_ATTEMPTS = 30

# Default poll interval if AS doesn't specify `wait` (seconds)
DEFAULT_POLL_WAIT_S = 5


class GnapAccessTokenProvider:
    """
    Provides GNAP access tokens for Kiota request adapters.

    This class manages the token lifecycle:
    1. Check the token store for a valid cached token
    2. If within grace period or expired, try token rotation
    3. If no token or rotation fails, request a new grant
    4. If the AS requires interaction, throw with details
    5. Store the token and return it

    Example::

        provider = GnapAccessTokenProvider(grant_manager, token_store, access_rights)
        provider.events.on("token:acquired", lambda e: print(f"New token: {e}"))
        token = await provider.get_authorization_token("https://wallet.example/payments")
    """

    def __init__(
        self,
        grant_manager: GnapGrantManager,
        token_store: Any,
        access_rights: list[AccessRight],
        interaction: Optional[InteractionConfig] = None,
    ) -> None:
        self.events = GnapEventEmitter()
        self._grant_manager = grant_manager
        self._token_store = token_store
        self._access_rights = access_rights
        self._interaction = interaction
        self._inflight: dict[str, asyncio.Task[Optional[str]]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def get_authorization_token(
        self,
        url: Optional[str] = None,
        additional_context: Optional[dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Get a valid GNAP access token.

        Implements the Kiota AccessTokenProvider pattern with concurrent
        acquisition guarding to prevent duplicate grants.

        Args:
            url: Target URL (used as scope key)
            additional_context: Optional Kiota context

        Returns:
            Access token string, or None if unauthenticated
        """
        scope_key = self._build_scope_key()

        # 1. Check cache — use peek() to avoid pruning tokens we may rotate
        if hasattr(self._token_store, "peek"):
            cached = await self._token_store.peek(scope_key)
        else:
            cached = await self._token_store.get(scope_key)
        if cached and self._is_token_fresh(cached):
            return cached.value

        # 2. Concurrent acquisition guard
        if scope_key not in self._locks:
            self._locks[scope_key] = asyncio.Lock()

        async with self._locks[scope_key]:
            # Re-check after acquiring lock
            if hasattr(self._token_store, "peek"):
                cached = await self._token_store.peek(scope_key)
            else:
                cached = await self._token_store.get(scope_key)
            if cached and self._is_token_fresh(cached):
                return cached.value

            return await self._acquire_token(scope_key)

    async def _acquire_token(self, scope_key: str) -> Optional[str]:
        """Internal: acquire a token via rotation or new grant."""
        # 1. Peek at expired token for rotation
        peeked = None
        if hasattr(self._token_store, "peek"):
            peeked = await self._token_store.peek(scope_key)

        stale = peeked
        if stale and stale.management_uri and stale.value:
            try:
                new_value = await self._grant_manager.rotate_token(
                    stale.management_uri, stale.value
                )
                refreshed = TokenInfo(
                    value=new_value,
                    management_uri=stale.management_uri,
                    access=stale.access,
                    expires_at=time.time() + 3600,  # Default 1 hour
                    flags=stale.flags,
                    continuation=stale.continuation,
                )
                await self._token_store.set(scope_key, refreshed)
                self.events.emit("token:rotated", {
                    "scope_key": scope_key,
                    "management_uri": stale.management_uri,
                })
                return refreshed.value
            except Exception as exc:
                self.events.emit("token:rotation_failed", {
                    "scope_key": scope_key,
                    "error": str(exc),
                })
                await self._token_store.delete(scope_key)

        # 2. Request a new grant
        grant_response = await self._grant_manager.request_grant(
            self._access_rights, self._interaction
        )

        # 3. Handle immediate token issuance
        if grant_response.access_token:
            token_info = self._build_token_info(grant_response)
            await self._token_store.set(scope_key, token_info)
            self.events.emit("token:acquired", {
                "scope_key": scope_key,
                "expires_in": grant_response.access_token.expires_in,
                "has_management_uri": bool(grant_response.access_token.manage),
            })
            return token_info.value

        # 4. Handle interaction-required
        if grant_response.interact:
            self.events.emit("grant:interaction_required", {
                "redirect": grant_response.interact.redirect,
                "user_code": grant_response.interact.user_code,
            })
            raise GnapInteractionRequiredError(
                redirect_url=grant_response.interact.redirect,
                user_code=grant_response.interact.user_code,
                user_code_uri=grant_response.interact.user_code_uri,
                finish_nonce=grant_response.interact.finish,
                continue_uri=(
                    grant_response.continuation.uri
                    if grant_response.continuation
                    else None
                ),
                continue_token=(
                    grant_response.continuation.access_token
                    if grant_response.continuation
                    else None
                ),
            )

        return None

    async def continue_grant(
        self,
        continue_uri: str,
        continue_token: str,
        interact_ref: str,
    ) -> str:
        """
        Continue a pending grant after interaction.

        Args:
            continue_uri: Continuation URI from grant response
            continue_token: Continuation access token
            interact_ref: Interaction reference from callback

        Returns:
            The new access token value

        Raises:
            GnapError: If continuation fails
            RuntimeError: If no token in response
        """
        scope_key = self._build_scope_key()

        response = await self._grant_manager.continue_grant(
            continue_uri, continue_token, interact_ref
        )

        if not response.access_token:
            raise RuntimeError("Grant continuation did not return an access token")

        token_info = self._build_token_info(response)
        await self._token_store.set(scope_key, token_info)
        self.events.emit("token:acquired", {
            "scope_key": scope_key,
            "expires_in": response.access_token.expires_in,
            "has_management_uri": bool(response.access_token.manage),
        })
        return token_info.value

    async def poll_continuation(
        self,
        continue_uri: str,
        continue_token: str,
        interact_ref: str,
        max_attempts: int = MAX_POLL_ATTEMPTS,
    ) -> str:
        """
        Poll for continuation until the AS returns a token.

        Per RFC 9635 §5.2, the AS may respond with `continue.wait`
        indicating the client should poll again after N seconds.

        Args:
            continue_uri: Initial continuation URI
            continue_token: Continuation access token
            interact_ref: Interaction reference from callback
            max_attempts: Maximum polling attempts

        Returns:
            The access token value

        Raises:
            RuntimeError: If polling exhausted
        """
        current_uri = continue_uri
        current_token = continue_token

        for attempt in range(1, max_attempts + 1):
            self.events.emit("grant:polling", {
                "continue_uri": current_uri,
                "attempt": attempt,
            })

            try:
                response = await self._grant_manager.continue_grant(
                    current_uri, current_token, interact_ref
                )

                if response.access_token:
                    scope_key = self._build_scope_key()
                    token_info = self._build_token_info(response)
                    await self._token_store.set(scope_key, token_info)
                    self.events.emit("token:acquired", {
                        "scope_key": scope_key,
                        "expires_in": response.access_token.expires_in,
                        "has_management_uri": bool(response.access_token.manage),
                    })
                    return token_info.value

                if response.continuation:
                    wait_s = response.continuation.wait or DEFAULT_POLL_WAIT_S
                    current_uri = response.continuation.uri
                    current_token = response.continuation.access_token
                    await asyncio.sleep(wait_s)
                    continue

            except Exception as exc:
                self.events.emit("grant:error", {
                    "error": str(exc),
                    "attempt": attempt,
                })
                if attempt >= max_attempts:
                    raise

            await asyncio.sleep(DEFAULT_POLL_WAIT_S)

        raise RuntimeError(
            f"Continuation polling exhausted after {max_attempts} attempts"
        )

    def _is_token_fresh(self, token: TokenInfo) -> bool:
        """Check if a token is still valid (outside grace period)."""
        if token.expires_at is None:
            return True
        return time.time() < token.expires_at - REFRESH_GRACE_S

    def _build_token_info(
        self, grant_response: GrantResponse
    ) -> TokenInfo:
        """Build TokenInfo from a grant response."""
        at = grant_response.access_token
        assert at is not None

        return TokenInfo(
            value=at.value,
            management_uri=at.manage,
            access=at.access,
            flags=at.flags,
            expires_at=(
                time.time() + at.expires_in if at.expires_in else None
            ),
            continuation=(
                ContinuationInfo(
                    uri=grant_response.continuation.uri,
                    access_token=grant_response.continuation.access_token,
                    wait=grant_response.continuation.wait,
                )
                if grant_response.continuation
                else None
            ),
        )

    def _build_scope_key(self) -> str:
        """Build a stable scope key from the access rights."""
        return "|".join(
            sorted(
                f"{r.type}:{','.join(sorted(r.actions))}"
                for r in self._access_rights
            )
        )
