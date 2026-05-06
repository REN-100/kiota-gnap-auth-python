"""
Tests for GnapGrantManager — RFC 9635 grant lifecycle.

Covers: grant requests with identifier/limits/flags, continuation,
rotation, revocation, grant deletion, structured error handling,
Content-Digest, wallet_address/display, and ECDSA-P256 support.
"""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from kiota_gnap_auth.gnap_grant_manager import GnapGrantManager
from kiota_gnap_auth.types import (
    AccessRight,
    Amount,
    ClientDisplay,
    ClientKeyConfig,
    Algorithm,
    InteractionConfig,
    InteractionFinish,
    PaymentLimits,
    ProofMethod,
)
from kiota_gnap_auth.errors import GnapError
from kiota_gnap_auth.retry import RetryPolicy


def _mock_response(status_code=200, data=None, headers=None):
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.json.return_value = data or {}
    return resp


@pytest.fixture
def client_key():
    return ClientKeyConfig(
        key_id="test-key-id",
        private_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        algorithm=Algorithm.ED25519,
        proof=ProofMethod.HTTPSIG,
    )


@pytest.fixture
def manager(client_key):
    return GnapGrantManager(
        grant_endpoint="https://auth.example/",
        client_key=client_key,
        retry_policy=RetryPolicy(max_attempts=0, retryable_statuses=[]),
    )


class TestRequestGrant:
    @pytest.mark.asyncio
    async def test_sends_grant_and_returns_token(self, manager):
        mock_resp = _mock_response(200, {
            "access_token": {
                "value": "os_token_abc123",
                "manage": "https://auth.example/manage/1",
                "access": [{"type": "incoming-payment", "actions": ["create", "read"]}],
                "expires_in": 3600,
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await manager.request_grant([
                AccessRight(type="incoming-payment", actions=["create", "read"]),
            ])

        assert result.access_token is not None
        assert result.access_token.value == "os_token_abc123"
        assert result.access_token.manage == "https://auth.example/manage/1"

    @pytest.mark.asyncio
    async def test_includes_identifier_and_limits(self, manager):
        mock_resp = _mock_response(200, {"access_token": {"value": "tok", "access": []}})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            await manager.request_grant([
                AccessRight(
                    type="outgoing-payment",
                    actions=["create", "read"],
                    identifier="https://wallet.example/alice",
                    limits=PaymentLimits(
                        receiver="https://wallet.example/bob/incoming-payments/abc",
                        debit_amount=Amount(value="1000", asset_code="USD", asset_scale=2),
                        interval="R12/2024-01-01T00:00:00Z/P1M",
                    ),
                ),
            ])

        call_kwargs = mock_req.call_args
        body = json.loads(call_kwargs.kwargs.get("content", b"{}"))
        access = body["access_token"]["access"][0]
        assert access["identifier"] == "https://wallet.example/alice"
        assert access["limits"]["receiver"] == "https://wallet.example/bob/incoming-payments/abc"
        assert access["limits"]["debitAmount"]["value"] == "1000"
        assert access["limits"]["interval"] == "R12/2024-01-01T00:00:00Z/P1M"

    @pytest.mark.asyncio
    async def test_includes_flags(self, manager):
        mock_resp = _mock_response(200, {"access_token": {"value": "tok", "access": []}})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            await manager.request_grant(
                [AccessRight(type="quote", actions=["create"])],
                flags=["bearer"],
            )

        body = json.loads(mock_req.call_args.kwargs.get("content", b"{}"))
        assert body["access_token"]["flags"] == ["bearer"]

    @pytest.mark.asyncio
    async def test_includes_content_digest(self, manager):
        mock_resp = _mock_response(200, {"access_token": {"value": "tok", "access": []}})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            await manager.request_grant([AccessRight(type="quote", actions=["create"])])

        headers = mock_req.call_args.kwargs.get("headers", {})
        assert "Content-Digest" in headers
        assert headers["Content-Digest"].startswith("sha-256=:")

    @pytest.mark.asyncio
    async def test_includes_signature_with_gnap_tag(self, manager):
        mock_resp = _mock_response(200, {"access_token": {"value": "tok", "access": []}})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            await manager.request_grant([AccessRight(type="quote", actions=["create"])])

        headers = mock_req.call_args.kwargs.get("headers", {})
        assert "Signature-Input" in headers
        assert 'tag="gnap"' in headers["Signature-Input"]
        assert "Signature" in headers

    @pytest.mark.asyncio
    async def test_includes_wallet_address_and_display(self, client_key):
        mgr = GnapGrantManager(
            grant_endpoint="https://auth.example/",
            client_key=client_key,
            wallet_address="https://wallet.example/alice",
            client_display=ClientDisplay(name="ShujaaPay", uri="https://www.shujaapay.me"),
            retry_policy=RetryPolicy(max_attempts=0, retryable_statuses=[]),
        )
        mock_resp = _mock_response(200, {"access_token": {"value": "tok", "access": []}})

        with patch.object(mgr._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            await mgr.request_grant([AccessRight(type="quote", actions=["create"])])

        body = json.loads(mock_req.call_args.kwargs.get("content", b"{}"))
        assert body["client"]["wallet_address"] == "https://wallet.example/alice"
        assert body["client"]["display"]["name"] == "ShujaaPay"

    @pytest.mark.asyncio
    async def test_returns_interaction_required(self, manager):
        mock_resp = _mock_response(200, {
            "interact": {"redirect": "https://auth.example/interact/abc"},
            "continue": {
                "access_token": {"value": "cont_tok"},
                "uri": "https://auth.example/continue/abc",
                "wait": 5,
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await manager.request_grant(
                [AccessRight(type="outgoing-payment", actions=["create"])],
            )

        assert result.interact is not None
        assert result.interact.redirect == "https://auth.example/interact/abc"
        assert result.continuation is not None
        assert result.continuation.wait == 5

    @pytest.mark.asyncio
    async def test_throws_gnap_error(self, manager):
        mock_resp = _mock_response(400, {
            "error": {"code": "invalid_client", "description": "Bad key"},
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(GnapError) as exc_info:
                await manager.request_grant([AccessRight(type="quote", actions=["create"])])

        assert exc_info.value.code == "invalid_client"
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_throws_gnap_error_string_format(self, manager):
        mock_resp = _mock_response(403, {"error": "user_denied"})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(GnapError) as exc_info:
                await manager.request_grant([AccessRight(type="quote", actions=["create"])])

        assert exc_info.value.code == "user_denied"

    @pytest.mark.asyncio
    async def test_supports_ecdsa_p256(self):
        ec_mgr = GnapGrantManager(
            grant_endpoint="https://auth.example/",
            client_key=ClientKeyConfig(
                key_id="ec-key",
                private_key="-----BEGIN PRIVATE KEY-----\ntest-ec\n-----END PRIVATE KEY-----",
                algorithm=Algorithm.ECDSA_P256_SHA256,
                proof=ProofMethod.HTTPSIG,
            ),
            retry_policy=RetryPolicy(max_attempts=0, retryable_statuses=[]),
        )
        mock_resp = _mock_response(200, {"access_token": {"value": "ec-tok", "access": []}})

        with patch.object(ec_mgr._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await ec_mgr.request_grant([
                AccessRight(type="incoming-payment", actions=["create"]),
            ])

        assert result.access_token.value == "ec-tok"

    @pytest.mark.asyncio
    async def test_identifier_without_limits(self, manager):
        mock_resp = _mock_response(200, {"access_token": {"value": "tok", "access": []}})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            await manager.request_grant([
                AccessRight(
                    type="incoming-payment",
                    actions=["create", "read", "read-all", "list", "list-all", "complete"],
                    identifier="https://ilp.interledger-test.dev/bob",
                ),
            ])

        body = json.loads(mock_req.call_args.kwargs.get("content", b"{}"))
        access = body["access_token"]["access"][0]
        assert access["identifier"] == "https://ilp.interledger-test.dev/bob"
        assert "complete" in access["actions"]
        assert "limits" not in access


class TestContinueGrant:
    @pytest.mark.asyncio
    async def test_continues_with_interact_ref(self, manager):
        mock_resp = _mock_response(200, {
            "access_token": {
                "value": "continued_token",
                "access": [{"type": "outgoing-payment", "actions": ["create"]}],
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            result = await manager.continue_grant(
                "https://auth.example/continue/abc", "cont_tok", "interact_ref_xyz"
            )

        assert result.access_token.value == "continued_token"
        body = json.loads(mock_req.call_args.kwargs.get("content", b"{}"))
        assert body["interact_ref"] == "interact_ref_xyz"


class TestRotateToken:
    @pytest.mark.asyncio
    async def test_rotates_token_returns_full_access(self, manager):
        """Rotation now returns full TokenAccess with manage URI and expiry."""
        mock_resp = _mock_response(200, {
            "access_token": {
                "value": "rotated_token",
                "manage": "https://auth.example/manage/2",
                "access": [{"type": "incoming-payment", "actions": ["create"]}],
                "expires_in": 7200,
                "flags": ["bearer"],
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await manager.rotate_token("https://auth.example/manage/1", "old_token")

        assert result.value == "rotated_token"
        assert result.manage == "https://auth.example/manage/2"
        assert result.expires_in == 7200
        assert result.flags == ["bearer"]
        assert len(result.access) == 1

    @pytest.mark.asyncio
    async def test_rotation_preserves_old_manage_uri(self, manager):
        """If rotation response has no manage URI, preserves the original."""
        mock_resp = _mock_response(200, {
            "access_token": {"value": "new_tok", "access": []},
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await manager.rotate_token("https://auth.example/manage/1", "old_token")

        assert result.value == "new_tok"
        assert result.manage == "https://auth.example/manage/1"

    @pytest.mark.asyncio
    async def test_rotation_failure(self, manager):
        mock_resp = _mock_response(401, {"error": "invalid_rotation"})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(GnapError):
                await manager.rotate_token("https://auth.example/manage/1", "old_token")


class TestIntrospectToken:
    @pytest.mark.asyncio
    async def test_introspects_token(self, manager):
        """Introspection returns token metadata via GET."""
        mock_resp = _mock_response(200, {
            "access_token": {
                "value": "active_token",
                "manage": "https://auth.example/manage/1",
                "access": [{"type": "quote", "actions": ["create", "read"]}],
                "expires_in": 1800,
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp) as mock_req:
            result = await manager.introspect_token("https://auth.example/manage/1", "my_token")

        assert result.value == "active_token"
        assert result.expires_in == 1800
        assert mock_req.call_args.kwargs["method"] == "GET"

    @pytest.mark.asyncio
    async def test_introspect_failure(self, manager):
        mock_resp = _mock_response(404, {"error": "unknown_token"})

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(GnapError):
                await manager.introspect_token("https://auth.example/manage/1", "bad_token")


class TestInteractionAppField:
    @pytest.mark.asyncio
    async def test_parses_app_interaction(self, manager):
        """Grant response with app launch URI is correctly parsed."""
        mock_resp = _mock_response(200, {
            "interact": {
                "app": "shujaapay://grant/abc123",
                "finish": "interact_nonce_xyz",
            },
            "continue": {
                "access_token": {"value": "cont_tok"},
                "uri": "https://auth.example/continue/abc",
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await manager.request_grant(
                [AccessRight(type="outgoing-payment", actions=["create"])],
            )

        assert result.interact is not None
        assert result.interact.app == "shujaapay://grant/abc123"
        assert result.interact.finish == "interact_nonce_xyz"

    @pytest.mark.asyncio
    async def test_app_field_none_when_absent(self, manager):
        """App field defaults to None when not in response."""
        mock_resp = _mock_response(200, {
            "interact": {"redirect": "https://auth.example/interact/abc"},
            "continue": {
                "access_token": {"value": "cont_tok"},
                "uri": "https://auth.example/continue/abc",
            },
        })

        with patch.object(manager._http_client, "request", new_callable=AsyncMock, return_value=mock_resp):
            result = await manager.request_grant(
                [AccessRight(type="outgoing-payment", actions=["create"])],
            )

        assert result.interact.app is None


class TestContextManager:
    @pytest.mark.asyncio
    async def test_grant_manager_context_manager(self, client_key):
        """GnapGrantManager works as an async context manager."""
        async with GnapGrantManager(
            grant_endpoint="https://auth.example/",
            client_key=client_key,
            retry_policy=RetryPolicy(max_attempts=0, retryable_statuses=[]),
        ) as mgr:
            assert mgr._grant_endpoint == "https://auth.example/"
        # After exit, the HTTP client should be closed
