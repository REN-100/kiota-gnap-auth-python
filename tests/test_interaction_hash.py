"""
Tests for interaction hash verification (RFC 9635 §4.2.3).
"""

import pytest

from kiota_gnap_auth.interaction_hash import (
    compute_interaction_hash,
    verify_interaction_hash,
)


class TestComputeInteractionHash:
    def test_sha256(self):
        h = compute_interaction_hash(
            client_nonce="client-nonce-123",
            server_nonce="server-nonce-456",
            interact_ref="interact-ref-789",
            grant_endpoint="https://auth.example/",
            hash_method="sha-256",
        )
        assert isinstance(h, str)
        assert len(h) > 20

    def test_sha512(self):
        h = compute_interaction_hash(
            client_nonce="client-nonce-123",
            server_nonce="server-nonce-456",
            interact_ref="interact-ref-789",
            grant_endpoint="https://auth.example/",
            hash_method="sha-512",
        )
        assert isinstance(h, str)
        # SHA-512 hash is longer than SHA-256
        h256 = compute_interaction_hash(
            client_nonce="client-nonce-123",
            server_nonce="server-nonce-456",
            interact_ref="interact-ref-789",
            grant_endpoint="https://auth.example/",
            hash_method="sha-256",
        )
        assert len(h) > len(h256)

    def test_defaults_to_sha256(self):
        h1 = compute_interaction_hash(
            client_nonce="a", server_nonce="b",
            interact_ref="c", grant_endpoint="d",
        )
        h2 = compute_interaction_hash(
            client_nonce="a", server_nonce="b",
            interact_ref="c", grant_endpoint="d",
            hash_method="sha-256",
        )
        assert h1 == h2

    def test_unsupported_hash_method(self):
        with pytest.raises(ValueError, match="Unsupported"):
            compute_interaction_hash(
                client_nonce="a", server_nonce="b",
                interact_ref="c", grant_endpoint="d",
                hash_method="sha-1024",
            )


class TestVerifyInteractionHash:
    def test_valid_hash(self):
        h = compute_interaction_hash(
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir", grant_endpoint="https://auth.example/",
        )
        assert verify_interaction_hash(
            received_hash=h,
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir", grant_endpoint="https://auth.example/",
        ) is True

    def test_tampered_hash(self):
        assert verify_interaction_hash(
            received_hash="tampered-hash-value",
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir", grant_endpoint="https://auth.example/",
        ) is False

    def test_different_interact_ref(self):
        h = compute_interaction_hash(
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir1", grant_endpoint="https://auth.example/",
        )
        assert verify_interaction_hash(
            received_hash=h,
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir2", grant_endpoint="https://auth.example/",
        ) is False

    def test_different_grant_endpoint(self):
        h = compute_interaction_hash(
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir", grant_endpoint="https://auth.example/",
        )
        assert verify_interaction_hash(
            received_hash=h,
            client_nonce="cn", server_nonce="sn",
            interact_ref="ir", grant_endpoint="https://evil.example/",
        ) is False
