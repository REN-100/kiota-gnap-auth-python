"""
Tests for GnapAccessTokenProvider.

Covers: caching, rotation, concurrent acquisition, events,
interaction handling, and continuation.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kiota_gnap_auth.gnap_access_token_provider import GnapAccessTokenProvider
from kiota_gnap_auth.token_store import InMemoryTokenStore
from kiota_gnap_auth.errors import GnapInteractionRequiredError
from kiota_gnap_auth.types import (
    AccessRight,
    ContinuationInfo,
    GrantResponse,
    InteractionResponse,
    TokenAccess,
    TokenInfo,
)


@pytest.fixture
def access_rights():
    return [AccessRight(type="incoming-payment", actions=["create", "read"])]


@pytest.fixture
def mock_grant_manager():
    mgr = MagicMock()
    mgr.request_grant = AsyncMock()
    mgr.continue_grant = AsyncMock()
    mgr.rotate_token = AsyncMock()
    return mgr


@pytest.fixture
def token_store():
    return InMemoryTokenStore()


@pytest.fixture
def provider(mock_grant_manager, token_store, access_rights):
    return GnapAccessTokenProvider(
        grant_manager=mock_grant_manager,
        token_store=token_store,
        access_rights=access_rights,
    )


class TestGetAuthorizationToken:
    @pytest.mark.asyncio
    async def test_returns_cached_token(self, provider, token_store, access_rights):
        scope_key = provider._build_scope_key()
        await token_store.set(scope_key, TokenInfo(
            value="cached_tok",
            expires_at=time.time() + 3600,
        ))

        result = await provider.get_authorization_token()
        assert result == "cached_tok"

    @pytest.mark.asyncio
    async def test_requests_new_grant(self, provider, mock_grant_manager):
        mock_grant_manager.request_grant.return_value = GrantResponse(
            access_token=TokenAccess(
                value="new_tok",
                manage="https://auth.example/manage/1",
                expires_in=3600,
            ),
        )

        result = await provider.get_authorization_token()
        assert result == "new_tok"
        mock_grant_manager.request_grant.assert_called_once()

    @pytest.mark.asyncio
    async def test_stores_acquired_token(self, provider, mock_grant_manager, token_store):
        mock_grant_manager.request_grant.return_value = GrantResponse(
            access_token=TokenAccess(
                value="stored_tok",
                manage="https://auth.example/manage/1",
                expires_in=3600,
            ),
        )

        await provider.get_authorization_token()
        scope_key = provider._build_scope_key()
        stored = await token_store.get(scope_key)
        assert stored is not None
        assert stored.value == "stored_tok"

    @pytest.mark.asyncio
    async def test_throws_interaction_required(self, provider, mock_grant_manager):
        mock_grant_manager.request_grant.return_value = GrantResponse(
            interact=InteractionResponse(redirect="https://auth.example/interact/abc"),
            continuation=ContinuationInfo(
                uri="https://auth.example/continue/abc",
                access_token="cont_tok",
                wait=5,
            ),
        )

        with pytest.raises(GnapInteractionRequiredError) as exc_info:
            await provider.get_authorization_token()

        assert exc_info.value.redirect_url == "https://auth.example/interact/abc"
        assert exc_info.value.continue_uri == "https://auth.example/continue/abc"

    @pytest.mark.asyncio
    async def test_rotation_on_expired_token(self, provider, mock_grant_manager, token_store):
        scope_key = provider._build_scope_key()
        await token_store.set(scope_key, TokenInfo(
            value="old_tok",
            management_uri="https://auth.example/manage/1",
            expires_at=time.time() - 100,  # expired
        ))

        mock_grant_manager.rotate_token.return_value = TokenAccess(
            value="rotated_tok",
            manage="https://auth.example/manage/2",
            expires_in=7200,
        )

        result = await provider.get_authorization_token()
        assert result == "rotated_tok"
        mock_grant_manager.rotate_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_fallback_on_rotation_failure(self, provider, mock_grant_manager, token_store):
        scope_key = provider._build_scope_key()
        await token_store.set(scope_key, TokenInfo(
            value="old_tok",
            management_uri="https://auth.example/manage/1",
            expires_at=time.time() - 100,
        ))

        mock_grant_manager.rotate_token.side_effect = RuntimeError("rotation failed")
        mock_grant_manager.request_grant.return_value = GrantResponse(
            access_token=TokenAccess(value="fallback_tok", expires_in=3600),
        )

        result = await provider.get_authorization_token()
        assert result == "fallback_tok"


class TestEvents:
    @pytest.mark.asyncio
    async def test_emits_token_acquired(self, provider, mock_grant_manager):
        events = []
        provider.events.on("token:acquired", lambda d: events.append(d))

        mock_grant_manager.request_grant.return_value = GrantResponse(
            access_token=TokenAccess(value="event_tok", expires_in=3600),
        )

        await provider.get_authorization_token()
        assert len(events) == 1
        assert events[0]["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_emits_token_rotated(self, provider, mock_grant_manager, token_store):
        events = []
        provider.events.on("token:rotated", lambda d: events.append(d))

        scope_key = provider._build_scope_key()
        await token_store.set(scope_key, TokenInfo(
            value="old", management_uri="https://auth.example/manage/1",
            expires_at=time.time() - 100,
        ))
        mock_grant_manager.rotate_token.return_value = TokenAccess(
            value="rotated", manage="https://auth.example/manage/1", expires_in=3600,
        )

        await provider.get_authorization_token()
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_emits_rotation_failed(self, provider, mock_grant_manager, token_store):
        events = []
        provider.events.on("token:rotation_failed", lambda d: events.append(d))

        scope_key = provider._build_scope_key()
        await token_store.set(scope_key, TokenInfo(
            value="old", management_uri="https://auth.example/manage/1",
            expires_at=time.time() - 100,
        ))
        mock_grant_manager.rotate_token.side_effect = RuntimeError("fail")
        mock_grant_manager.request_grant.return_value = GrantResponse(
            access_token=TokenAccess(value="new", expires_in=3600),
        )

        await provider.get_authorization_token()
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_emits_interaction_required(self, provider, mock_grant_manager):
        events = []
        provider.events.on("grant:interaction_required", lambda d: events.append(d))

        mock_grant_manager.request_grant.return_value = GrantResponse(
            interact=InteractionResponse(redirect="https://auth.example/interact/abc"),
            continuation=ContinuationInfo(
                uri="https://auth.example/continue/abc",
                access_token="cont_tok",
            ),
        )

        with pytest.raises(GnapInteractionRequiredError):
            await provider.get_authorization_token()

        assert len(events) == 1
        assert events[0]["redirect"] == "https://auth.example/interact/abc"


class TestContinueGrant:
    @pytest.mark.asyncio
    async def test_continues_and_stores(self, provider, mock_grant_manager, token_store):
        mock_grant_manager.continue_grant.return_value = GrantResponse(
            access_token=TokenAccess(value="continued_tok", expires_in=3600),
        )

        result = await provider.continue_grant(
            "https://auth.example/continue/abc", "cont_tok", "interact_ref"
        )
        assert result == "continued_tok"

        scope_key = provider._build_scope_key()
        stored = await token_store.get(scope_key)
        assert stored.value == "continued_tok"

    @pytest.mark.asyncio
    async def test_throws_if_no_token(self, provider, mock_grant_manager):
        mock_grant_manager.continue_grant.return_value = GrantResponse()

        with pytest.raises(RuntimeError, match="did not return"):
            await provider.continue_grant(
                "https://auth.example/continue/abc", "cont_tok", "interact_ref"
            )
