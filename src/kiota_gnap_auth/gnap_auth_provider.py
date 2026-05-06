"""
GNAP Authentication Provider for Kiota (Python)

Implements Kiota's AuthenticationProvider interface to handle
GNAP (RFC 9635) authorization for generated SDK clients.

Part of the ShujaaPay Open Payments ecosystem.

@see https://www.rfc-editor.org/rfc/rfc9635
@see https://www.shujaapay.me
"""

from __future__ import annotations

from typing import Any, Optional

from kiota_abstractions.authentication import AuthenticationProvider
from kiota_abstractions.request_information import RequestInformation

from .gnap_access_token_provider import GnapAccessTokenProvider
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
            GnapAuthOptions(
                grant_endpoint="https://auth.wallet.example/",
                client_key=ClientKeyConfig(
                    key_id="my-key",
                    private_key=my_private_key,
                    algorithm=Algorithm.ED25519,
                    proof=ProofMethod.HTTPSIG,
                ),
                access_rights=[
                    AccessRight(
                        type="incoming-payment",
                        actions=["create", "read"],
                        identifier="https://wallet.example/alice",
                    ),
                ],
                wallet_address="https://wallet.example/alice",
                client_display=ClientDisplay(name="ShujaaPay"),
            )
        )

        adapter = HttpxRequestAdapter(auth_provider)
        client = OpenPaymentsClient(adapter)
    """

    def __init__(
        self, options: Optional[GnapAuthOptions] = None, **kwargs: Any
    ) -> None:
        if options is None:
            options = GnapAuthOptions(**kwargs)

        self._options = options
        self._grant_manager = GnapGrantManager(
            grant_endpoint=options.grant_endpoint,
            client_key=options.client_key,
            wallet_address=options.wallet_address,
            client_display=options.client_display,
        )
        self._token_store = options.token_store or InMemoryTokenStore()
        self._token_provider = GnapAccessTokenProvider(
            grant_manager=self._grant_manager,
            token_store=self._token_store,
            access_rights=options.access_rights,
            interaction=options.interaction,
        )
        self._allowed_hosts = set(options.allowed_hosts) if options.allowed_hosts else None

    @property
    def events(self):
        """Access the event emitter for lifecycle monitoring."""
        return self._token_provider.events

    @property
    def token_provider(self) -> GnapAccessTokenProvider:
        """Access the underlying token provider."""
        return self._token_provider

    async def authenticate_request(
        self,
        request: RequestInformation,
        additional_authentication_context: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Authenticate an outgoing HTTP request.

        1. Checks allowed hosts (if configured)
        2. Obtains a valid GNAP access token
        3. Adds the Authorization header (GNAP token)
        4. Signs the request with HTTP Message Signatures

        This method is called automatically by Kiota's request adapter
        before each API call.
        """
        # Check allowed hosts
        if self._allowed_hosts and request.url:
            from urllib.parse import urlparse
            host = urlparse(request.url).hostname or ""
            if host not in self._allowed_hosts:
                return  # Skip authentication for non-allowed hosts

        # Get or acquire a valid access token
        token = await self._token_provider.get_authorization_token(
            url=request.url
        )

        if token is None:
            raise RuntimeError("Failed to obtain GNAP access token")

        # Add GNAP authorization header
        request.headers.try_add("Authorization", f"GNAP {token}")

        # Sign the request with HTTP Message Signatures (RFC 9421)
        await self._sign_request(request)

    async def _sign_request(self, request: RequestInformation) -> None:
        """Sign the request using RFC 9421 HTTP Message Signatures."""
        from .http_signature_signer import sign_request

        await sign_request(
            request=request,
            client_key=self._options.client_key,
        )

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        await self._grant_manager.close()

    async def __aenter__(self) -> "GnapAuthenticationProvider":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()
