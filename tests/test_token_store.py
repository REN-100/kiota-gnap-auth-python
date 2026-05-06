"""
Tests for in-memory token store.
"""

import time

import pytest

from kiota_gnap_auth.token_store import InMemoryTokenStore
from kiota_gnap_auth.types import TokenInfo


@pytest.fixture
def store():
    return InMemoryTokenStore()


class TestInMemoryTokenStore:
    @pytest.mark.asyncio
    async def test_returns_none_for_missing_key(self, store):
        result = await store.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_stores_and_retrieves(self, store):
        token = TokenInfo(value="tok_123")
        await store.set("scope", token)
        result = await store.get("scope")
        assert result is not None
        assert result.value == "tok_123"

    @pytest.mark.asyncio
    async def test_overwrites_existing(self, store):
        await store.set("scope", TokenInfo(value="old"))
        await store.set("scope", TokenInfo(value="new"))
        result = await store.get("scope")
        assert result.value == "new"

    @pytest.mark.asyncio
    async def test_deletes_token(self, store):
        await store.set("scope", TokenInfo(value="tok"))
        await store.delete("scope")
        assert await store.get("scope") is None

    @pytest.mark.asyncio
    async def test_clears_all(self, store):
        await store.set("a", TokenInfo(value="1"))
        await store.set("b", TokenInfo(value="2"))
        await store.clear()
        assert await store.get("a") is None
        assert await store.get("b") is None

    @pytest.mark.asyncio
    async def test_auto_prunes_expired(self, store):
        token = TokenInfo(value="expired", expires_at=time.time() - 10)
        await store.set("scope", token)
        result = await store.get("scope")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_valid_before_expiry(self, store):
        token = TokenInfo(value="valid", expires_at=time.time() + 3600)
        await store.set("scope", token)
        result = await store.get("scope")
        assert result is not None
        assert result.value == "valid"

    @pytest.mark.asyncio
    async def test_returns_token_without_expiry(self, store):
        token = TokenInfo(value="forever")
        await store.set("scope", token)
        result = await store.get("scope")
        assert result is not None

    @pytest.mark.asyncio
    async def test_peek_returns_expired_token(self, store):
        token = TokenInfo(value="stale", expires_at=time.time() - 10, management_uri="https://x")
        await store.set("scope", token)
        # get() should prune
        assert await store.get("scope") is None
        # but peek should return (re-add for peek test)
        await store.set("scope", TokenInfo(value="stale2", expires_at=time.time() - 10))
        peeked = await store.peek("scope")
        assert peeked is not None
        assert peeked.value == "stale2"

    @pytest.mark.asyncio
    async def test_independent_scopes(self, store):
        await store.set("a", TokenInfo(value="1"))
        await store.set("b", TokenInfo(value="2"))
        assert (await store.get("a")).value == "1"
        assert (await store.get("b")).value == "2"
