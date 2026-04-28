"""
GNAP Authentication Provider for Kiota (Python)

Implements Kiota's AuthenticationProvider interface to handle
GNAP (RFC 9635) authorization for generated SDK clients.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from kiota_abstractions.authentication import AuthenticationProvider
from kiota_abstractions.request_information import RequestInformation

from .gnap_grant_manager import GnapGrantManager
from .token_store import InMemoryTokenStore
from .types import GnapAuthOptions, TokenInfo


class GnapAuthenticationProvider(AuthenticationProvider):
    """
    Kiota AuthenticationProvider that handles GNAP authorization.

    Manages the complete GNAP lifecycle:
    1. Requests grants from the authorization server
    2. Handles interaction (redirect/user_code) if required
    3. Acquires and caches access tokens
    4. Automatically refreshes expired tokens
    5. Signs requests with HTTP Message Signatures (RFC 9421)

    Example::

        auth_provider = GnapAuthenticationProvider(
            grant_endpoint="https://auth.wallet.example/",
            client_key=ClientKeyConfig(
                key_id="my-key",
                private_key=my_private_key,
                algorithm=Algorithm.ED25519,
                proof=ProofMethod.HTTPSIG,
            ),
            access_rights=[
                AccessRight(type="incoming-payment", actions=["create", "read"]),
            ],
        )

        adapter = HttpxRequestAdapter(auth_provider)
        client = OpenPaymentsClient(adapter)
    """

    def __init__(self, options: Optional[GnapAuthOptions] = None, **kwargs: Any) -> None:
        if options is None:
            options = GnapAuthOptions(**kwargs)

        self._options = options
        self._grant_manager = GnapGrantManager(
            grant_endpoint=options.grant_endpoint,
            client_key=options.client_key,
        )
        self._token_store = InMemoryTokenStore()

    async def authenticate_request(
        self,
        request: RequestInformation,
        additional_authentication_context: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Authenticate an outgoing HTTP request.

        1. Obtains a valid GNAP access token
        2. Adds the Authorization header (GNAP token)
        3. Signs the request with HTTP Message Signatures

        This method is called automatically by Kiota's request adapter
        before each API call.
        """
        # Get or acquire a valid access token
        token = await self._get_valid_token()

        if token is None:
            raise RuntimeError("Failed to obtain GNAP access token")

        # Add GNAP authorization header
        request.headers.try_add("Authorization", f"GNAP {token.value}")

        # Sign the request with HTTP Message Signatures (RFC 9421)
        await self._sign_request(request)

    async def _get_valid_token(self) -> Optional[TokenInfo]:
        """Get a valid token from store, or acquire a new one."""
        import time

        scope_key = self._compute_scope_key()
        token = await self._token_store.get(scope_key)

        # Check if token exists and is not expired
        if token is not None:
            if token.expires_at is None or token.expires_at > time.time():
                return token
            # Token expired - try rotation
            if token.management_uri:
                new_value = await self._grant_manager.rotate_token(
                    token.management_uri, token.value
                )
                token.value = new_value
                await self._token_store.set(scope_key, token)
                return token

        # No valid token - request a new grant
        grant = await self._grant_manager.request_grant(
            self._options.access_rights,
            self._options.interaction,
        )

        if grant.access_token is not None:
            new_token = TokenInfo(
                value=grant.access_token.value,
                management_uri=grant.access_token.manage_uri,
                access=grant.access_token.access,
                expires_at=(
                    time.time() + grant.access_token.expires_in
                    if grant.access_token.expires_in
                    else None
                ),
            )
            await self._token_store.set(scope_key, new_token)
            return new_token

        return None

    async def _sign_request(self, request: RequestInformation) -> None:
        """Sign the request using RFC 9421 HTTP Message Signatures."""
        from .http_signature_signer import sign_request

        await sign_request(
            request=request,
            client_key=self._options.client_key,
        )

    def _compute_scope_key(self) -> str:
        """Compute a cache key from the requested access rights."""
        rights = sorted(
            f"{r.type}:{','.join(sorted(r.actions))}"
            for r in self._options.access_rights
        )
        return "|".join(rights)
