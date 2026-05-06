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
