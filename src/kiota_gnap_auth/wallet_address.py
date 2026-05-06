"""
Wallet Address Resolution — Open Payments

Resolves Open Payments wallet addresses to discover the
authorization server, resource server, and default currency.

Per the Open Payments specification, a wallet address (e.g.,
``https://wallet.example/alice``) is an HTTPS URL that, when
resolved with ``Accept: application/json``, returns metadata
including the ``authServer`` URL needed for GNAP grant requests.

@see https://openpayments.dev/identity/wallet-addresses/
@see https://www.shujaapay.me
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger("kiota_gnap_auth.wallet_address")


@dataclass
class WalletAddressInfo:
    """
    Resolved wallet address metadata.

    Example::

        info = await resolve_wallet_address("https://ilp.rafiki.money/alice")
        print(info.auth_server)  # https://auth.rafiki.money
        print(info.asset_code)   # USD
    """

    id: str
    """The canonical wallet address URL."""

    auth_server: str
    """Authorization server URL for GNAP grant requests."""

    resource_server: str
    """Resource server URL for Open Payments API calls."""

    asset_code: str
    """Default asset code (e.g., 'USD', 'KES', 'EUR')."""

    asset_scale: int
    """Decimal places for the default asset."""

    public_name: Optional[str] = None
    """Human-readable name of the wallet address owner."""


async def resolve_wallet_address(
    wallet_address_url: str,
    *,
    timeout: float = 10.0,
) -> WalletAddressInfo:
    """
    Resolve an Open Payments wallet address to discover its metadata.

    Performs a GET request to the wallet address URL with
    ``Accept: application/json`` to retrieve the wallet address
    metadata document. This is the standard way to discover the
    authorization server URL needed for GNAP grant requests.

    Args:
        wallet_address_url: The wallet address URL to resolve
            (e.g., ``https://wallet.example/alice``)
        timeout: HTTP request timeout in seconds

    Returns:
        Resolved wallet address information including auth server URL

    Raises:
        WalletAddressResolutionError: If resolution fails
        httpx.HTTPStatusError: On non-2xx response

    Example::

        info = await resolve_wallet_address("https://ilp.rafiki.money/alice")
        # Use info.auth_server as the GNAP grant endpoint
        manager = GnapGrantManager(
            grant_endpoint=info.auth_server,
            client_key=my_key,
            wallet_address=wallet_address_url,
        )
    """
    logger.info("Resolving wallet address: %s", wallet_address_url)

    # Normalize URL — ensure HTTPS
    url = wallet_address_url.strip()
    if url.startswith("$"):
        # Legacy payment pointer format: $wallet.example/alice -> https://wallet.example/alice
        url = f"https://{url[1:]}"
    elif not url.startswith("https://"):
        if url.startswith("http://"):
            raise WalletAddressResolutionError(
                f"Wallet addresses must use HTTPS: {url}"
            )
        url = f"https://{url}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(
                url,
                headers={
                    "Accept": "application/json",
                },
                follow_redirects=True,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise WalletAddressResolutionError(
                f"Failed to resolve wallet address {url}: "
                f"HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise WalletAddressResolutionError(
                f"Network error resolving wallet address {url}: {exc}"
            ) from exc

    data = response.json()

    # Validate required fields
    required_fields = ["id", "authServer", "resourceServer", "assetCode", "assetScale"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        raise WalletAddressResolutionError(
            f"Wallet address response missing required fields: {missing}"
        )

    info = WalletAddressInfo(
        id=data["id"],
        auth_server=data["authServer"],
        resource_server=data["resourceServer"],
        asset_code=data["assetCode"],
        asset_scale=data["assetScale"],
        public_name=data.get("publicName"),
    )
    logger.debug(
        "Resolved wallet address: auth_server=%s, asset=%s (scale=%d)",
        info.auth_server,
        info.asset_code,
        info.asset_scale,
    )
    return info


class WalletAddressResolutionError(Exception):
    """Error resolving an Open Payments wallet address."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class WalletAddressKey:
    """
    A JSON Web Key (JWK) bound to a wallet address.

    These keys are registered with an Open Payments authorization server
    and used to verify the identity of client instances making GNAP
    grant requests.

    @see https://openpayments.dev/apis/wallet-address-server/operations/get-wallet-address-keys/
    """

    kty: str
    """Key type (e.g., 'OKP' for Ed25519)."""

    crv: str
    """Curve (e.g., 'Ed25519')."""

    x: str
    """Public key (base64url-encoded)."""

    kid: Optional[str] = None
    """Key ID."""

    alg: Optional[str] = None
    """Algorithm (e.g., 'EdDSA')."""

    use: Optional[str] = None
    """Key usage (e.g., 'sig')."""


async def get_wallet_address_keys(
    wallet_address_url: str,
    *,
    timeout: float = 10.0,
) -> list[WalletAddressKey]:
    """
    Fetch the public keys bound to a wallet address.

    Performs an HTTP GET to ``{wallet_address}/jwks.json`` to retrieve the
    JWKS (JSON Web Key Set) associated with the wallet address.
    These keys are used by authorization servers to verify client identity.

    Args:
        wallet_address_url: The wallet address URL
        timeout: HTTP request timeout in seconds

    Returns:
        List of JWK public keys bound to the wallet address

    Raises:
        WalletAddressResolutionError: If resolution fails

    Example::

        keys = await get_wallet_address_keys("https://wallet.example/alice")
        for key in keys:
            print(f"{key.kid}: {key.kty}/{key.crv}")
    """
    logger.info("Fetching wallet address keys: %s", wallet_address_url)

    # Normalize URL (same logic as resolve_wallet_address)
    url = wallet_address_url.strip()
    if url.startswith("$"):
        url = f"https://{url[1:]}"
    elif not url.startswith("https://"):
        if url.startswith("http://"):
            raise WalletAddressResolutionError(
                f"Wallet addresses must use HTTPS: {url}"
            )
        url = f"https://{url}"

    # Append /jwks.json
    keys_url = f"{url.rstrip('/')}/jwks.json"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(
                keys_url,
                headers={
                    "Accept": "application/json",
                },
                follow_redirects=True,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise WalletAddressResolutionError(
                f"Failed to fetch wallet address keys {keys_url}: "
                f"HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise WalletAddressResolutionError(
                f"Network error fetching wallet address keys {keys_url}: {exc}"
            ) from exc

    data = response.json()

    if "keys" not in data or not isinstance(data["keys"], list):
        raise WalletAddressResolutionError(
            f"Wallet address keys response missing 'keys' array"
        )

    keys = []
    for jwk in data["keys"]:
        keys.append(
            WalletAddressKey(
                kty=jwk["kty"],
                crv=jwk["crv"],
                x=jwk["x"],
                kid=jwk.get("kid"),
                alg=jwk.get("alg"),
                use=jwk.get("use"),
            )
        )

    logger.debug("Found %d keys for wallet address %s", len(keys), wallet_address_url)
    return keys

