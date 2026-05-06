"""
Tests for wallet address resolution (Open Payments).
"""

import pytest
import httpx
import respx

from kiota_gnap_auth.wallet_address import (
    WalletAddressInfo,
    WalletAddressKey,
    WalletAddressResolutionError,
    resolve_wallet_address,
    get_wallet_address_keys,
)


VALID_WALLET_RESPONSE = {
    "id": "https://ilp.rafiki.money/alice",
    "publicName": "Alice",
    "authServer": "https://auth.rafiki.money",
    "resourceServer": "https://ilp.rafiki.money",
    "assetCode": "USD",
    "assetScale": 2,
}

VALID_JWKS_RESPONSE = {
    "keys": [
        {
            "kid": "key-1",
            "alg": "EdDSA",
            "use": "sig",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }
    ]
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


# --- Wallet Address Keys Tests ---


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_address_keys_success():
    """Fetches JWKS from wallet address /jwks.json."""
    respx.get("https://wallet.example/alice/jwks.json").mock(
        return_value=httpx.Response(200, json=VALID_JWKS_RESPONSE)
    )

    keys = await get_wallet_address_keys("https://wallet.example/alice")

    assert len(keys) == 1
    assert isinstance(keys[0], WalletAddressKey)
    assert keys[0].kty == "OKP"
    assert keys[0].crv == "Ed25519"
    assert keys[0].kid == "key-1"
    assert keys[0].alg == "EdDSA"
    assert keys[0].use == "sig"


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_address_keys_multiple():
    """Returns multiple keys."""
    multi_jwks = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": "key1-x", "kid": "key-1"},
            {"kty": "OKP", "crv": "Ed25519", "x": "key2-x", "kid": "key-2"},
        ]
    }
    respx.get("https://wallet.example/alice/jwks.json").mock(
        return_value=httpx.Response(200, json=multi_jwks)
    )

    keys = await get_wallet_address_keys("https://wallet.example/alice")
    assert len(keys) == 2


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_address_keys_payment_pointer():
    """Converts $ payment pointer for keys."""
    respx.get("https://wallet.example/alice/jwks.json").mock(
        return_value=httpx.Response(200, json=VALID_JWKS_RESPONSE)
    )

    keys = await get_wallet_address_keys("$wallet.example/alice")
    assert len(keys) == 1


@pytest.mark.asyncio
async def test_get_wallet_address_keys_rejects_http():
    """Rejects non-HTTPS for wallet address keys."""
    with pytest.raises(WalletAddressResolutionError, match="HTTPS"):
        await get_wallet_address_keys("http://wallet.example/alice")


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_address_keys_http_error():
    """Raises error on non-2xx response."""
    respx.get("https://wallet.example/alice/jwks.json").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )

    with pytest.raises(WalletAddressResolutionError, match="404"):
        await get_wallet_address_keys("https://wallet.example/alice")


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_address_keys_network_error():
    """Raises error on network failure."""
    respx.get("https://wallet.example/alice/jwks.json").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with pytest.raises(WalletAddressResolutionError, match="Network error"):
        await get_wallet_address_keys("https://wallet.example/alice")


@pytest.mark.asyncio
@respx.mock
async def test_get_wallet_address_keys_missing_keys_array():
    """Raises error when response has no keys array."""
    respx.get("https://wallet.example/alice/jwks.json").mock(
        return_value=httpx.Response(200, json={"not_keys": []})
    )

    with pytest.raises(WalletAddressResolutionError, match="keys"):
        await get_wallet_address_keys("https://wallet.example/alice")

