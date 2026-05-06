"""
Tests for wallet address resolution (Open Payments).
"""

import pytest
import httpx
import respx

from kiota_gnap_auth.wallet_address import (
    WalletAddressInfo,
    WalletAddressResolutionError,
    resolve_wallet_address,
)


VALID_WALLET_RESPONSE = {
    "id": "https://ilp.rafiki.money/alice",
    "publicName": "Alice",
    "authServer": "https://auth.rafiki.money",
    "resourceServer": "https://ilp.rafiki.money",
    "assetCode": "USD",
    "assetScale": 2,
}


@pytest.mark.asyncio
@respx.mock
async def test_resolve_wallet_address_success():
    """Resolves a wallet address and returns metadata."""
    respx.get("https://wallet.example/alice").mock(
        return_value=httpx.Response(200, json=VALID_WALLET_RESPONSE)
    )

    info = await resolve_wallet_address("https://wallet.example/alice")

    assert isinstance(info, WalletAddressInfo)
    assert info.id == "https://ilp.rafiki.money/alice"
    assert info.auth_server == "https://auth.rafiki.money"
    assert info.resource_server == "https://ilp.rafiki.money"
    assert info.asset_code == "USD"
    assert info.asset_scale == 2
    assert info.public_name == "Alice"


@pytest.mark.asyncio
@respx.mock
async def test_resolve_wallet_address_no_public_name():
    """Handles wallet addresses without publicName."""
    response_data = {**VALID_WALLET_RESPONSE}
    del response_data["publicName"]

    respx.get("https://wallet.example/bob").mock(
        return_value=httpx.Response(200, json=response_data)
    )

    info = await resolve_wallet_address("https://wallet.example/bob")
    assert info.public_name is None
    assert info.auth_server == "https://auth.rafiki.money"


@pytest.mark.asyncio
@respx.mock
async def test_resolve_legacy_payment_pointer():
    """Converts legacy $payment-pointer format to HTTPS URL."""
    respx.get("https://wallet.example/alice").mock(
        return_value=httpx.Response(200, json=VALID_WALLET_RESPONSE)
    )

    info = await resolve_wallet_address("$wallet.example/alice")
    assert info.auth_server == "https://auth.rafiki.money"


@pytest.mark.asyncio
async def test_resolve_rejects_http():
    """Rejects non-HTTPS wallet addresses."""
    with pytest.raises(WalletAddressResolutionError, match="HTTPS"):
        await resolve_wallet_address("http://wallet.example/alice")


@pytest.mark.asyncio
@respx.mock
async def test_resolve_missing_required_fields():
    """Raises error when required fields are missing."""
    incomplete = {"id": "https://wallet.example/alice"}
    respx.get("https://wallet.example/alice").mock(
        return_value=httpx.Response(200, json=incomplete)
    )

    with pytest.raises(WalletAddressResolutionError, match="missing required"):
        await resolve_wallet_address("https://wallet.example/alice")


@pytest.mark.asyncio
@respx.mock
async def test_resolve_http_error():
    """Raises error on non-2xx HTTP response."""
    respx.get("https://wallet.example/notfound").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )

    with pytest.raises(WalletAddressResolutionError, match="404"):
        await resolve_wallet_address("https://wallet.example/notfound")


@pytest.mark.asyncio
@respx.mock
async def test_resolve_network_error():
    """Raises error on network failure."""
    respx.get("https://wallet.example/down").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with pytest.raises(WalletAddressResolutionError, match="Network error"):
        await resolve_wallet_address("https://wallet.example/down")


@pytest.mark.asyncio
@respx.mock
async def test_resolve_kes_wallet():
    """Resolves a KES wallet address with correct currency info."""
    kes_response = {
        "id": "https://wallet.shujaapay.me/alice",
        "authServer": "https://auth.shujaapay.me",
        "resourceServer": "https://wallet.shujaapay.me",
        "assetCode": "KES",
        "assetScale": 2,
        "publicName": "Alice Wanjiku",
    }
    respx.get("https://wallet.shujaapay.me/alice").mock(
        return_value=httpx.Response(200, json=kes_response)
    )

    info = await resolve_wallet_address("https://wallet.shujaapay.me/alice")
    assert info.asset_code == "KES"
    assert info.public_name == "Alice Wanjiku"


@pytest.mark.asyncio
@respx.mock
async def test_resolve_auto_prepends_https():
    """Auto-prepends https:// to bare domain URLs."""
    respx.get("https://wallet.example/alice").mock(
        return_value=httpx.Response(200, json=VALID_WALLET_RESPONSE)
    )

    info = await resolve_wallet_address("wallet.example/alice")
    assert info.auth_server == "https://auth.rafiki.money"
