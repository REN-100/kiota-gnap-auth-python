"""
Tests for GNAP type definitions and Open Payments extensions.
"""

from kiota_gnap_auth.types import (
    AccessRight,
    Amount,
    ClientDisplay,
    ClientKeyConfig,
    GnapAuthOptions,
    PaymentLimits,
    TokenAccess,
    TokenInfo,
    Algorithm,
    ProofMethod,
)


class TestAmount:
    def test_create_usd(self):
        amt = Amount(value="1000", asset_code="USD", asset_scale=2)
        assert amt.value == "1000"
        assert amt.asset_code == "USD"
        assert amt.asset_scale == 2

    def test_to_dict(self):
        amt = Amount(value="50000", asset_code="KES", asset_scale=2)
        d = amt.to_dict()
        assert d == {"value": "50000", "assetCode": "KES", "assetScale": 2}


class TestPaymentLimits:
    def test_full_limits(self):
        limits = PaymentLimits(
            receiver="https://wallet.example/bob/incoming-payments/abc",
            debit_amount=Amount(value="1000", asset_code="USD", asset_scale=2),
            receive_amount=Amount(value="900", asset_code="EUR", asset_scale=2),
            interval="R12/2024-01-01T00:00:00Z/P1M",
        )
        d = limits.to_dict()
        assert d["receiver"] == "https://wallet.example/bob/incoming-payments/abc"
        assert d["debitAmount"]["value"] == "1000"
        assert d["receiveAmount"]["assetCode"] == "EUR"
        assert d["interval"] == "R12/2024-01-01T00:00:00Z/P1M"

    def test_empty_limits(self):
        limits = PaymentLimits()
        assert limits.to_dict() == {}

    def test_partial_limits(self):
        limits = PaymentLimits(
            receiver="https://wallet.example/bob/incoming-payments/abc",
        )
        d = limits.to_dict()
        assert "receiver" in d
        assert "debitAmount" not in d


class TestAccessRight:
    def test_basic_right(self):
        right = AccessRight(type="incoming-payment", actions=["create", "read"])
        assert right.type == "incoming-payment"
        assert right.actions == ["create", "read"]
        assert right.identifier is None
        assert right.limits is None

    def test_with_identifier(self):
        right = AccessRight(
            type="outgoing-payment",
            actions=["create"],
            identifier="https://wallet.example/alice",
        )
        assert right.identifier == "https://wallet.example/alice"

    def test_with_limits(self):
        right = AccessRight(
            type="outgoing-payment",
            actions=["create"],
            limits=PaymentLimits(
                receiver="https://wallet.example/bob/incoming-payments/abc",
            ),
        )
        assert right.limits is not None
        assert right.limits.receiver == "https://wallet.example/bob/incoming-payments/abc"


class TestTokenAccess:
    def test_manage_is_string(self):
        ta = TokenAccess(
            value="tok_123",
            manage="https://auth.example/manage/1",
        )
        assert ta.manage == "https://auth.example/manage/1"

    def test_flags(self):
        ta = TokenAccess(value="tok", flags=["bearer", "durable"])
        assert "bearer" in ta.flags
        assert "durable" in ta.flags


class TestAlgorithm:
    def test_ed25519_value(self):
        assert Algorithm.ED25519.value == "ed25519"

    def test_ecdsa_p256_value(self):
        assert Algorithm.ECDSA_P256_SHA256.value == "ecdsa-p256-sha256"


class TestClientDisplay:
    def test_full_display(self):
        d = ClientDisplay(
            name="ShujaaPay",
            uri="https://www.shujaapay.me",
            logo_uri="https://www.shujaapay.me/logo.png",
        )
        assert d.name == "ShujaaPay"
        assert d.uri == "https://www.shujaapay.me"
