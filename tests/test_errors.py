"""
Tests for GNAP error handling (RFC 9635 §3.6).
"""

import pytest

from kiota_gnap_auth.errors import (
    GnapError,
    GnapInteractionRequiredError,
    parse_gnap_error_response,
    RETRYABLE_ERROR_CODES,
)


class TestGnapError:
    def test_create_with_code_and_description(self):
        err = GnapError(code="invalid_client", description="Key not recognized")
        assert err.code == "invalid_client"
        assert err.description == "Key not recognized"
        assert "invalid_client" in str(err)

    def test_create_without_description(self):
        err = GnapError(code="request_denied")
        assert err.description is None
        assert "request_denied" in str(err)

    def test_status_code(self):
        err = GnapError(code="user_denied", status_code=403)
        assert err.status_code == 403
        assert "403" in str(err)

    def test_is_retryable_too_fast(self):
        err = GnapError(code="too_fast")
        assert err.is_retryable is True

    def test_is_not_retryable(self):
        err = GnapError(code="invalid_client")
        assert err.is_retryable is False

    def test_is_recoverable_with_continue(self):
        err = GnapError(
            code="too_fast",
            continue_uri="https://auth.example/continue/1",
            continue_token="cont_tok",
        )
        assert err.is_recoverable is True

    def test_is_not_recoverable(self):
        err = GnapError(code="request_denied")
        assert err.is_recoverable is False

    def test_retry_after(self):
        err = GnapError(code="too_fast", retry_after=5)
        assert err.retry_after == 5


class TestGnapInteractionRequiredError:
    def test_with_redirect(self):
        err = GnapInteractionRequiredError(
            redirect_url="https://auth.example/interact/abc",
        )
        assert err.redirect_url == "https://auth.example/interact/abc"
        assert err.code == "interaction_required"
        assert "Redirect" in str(err)

    def test_with_user_code(self):
        err = GnapInteractionRequiredError(
            user_code="A1B2-C3D4",
        )
        assert err.user_code == "A1B2-C3D4"
        assert "User code" in str(err)

    def test_with_continuation(self):
        err = GnapInteractionRequiredError(
            redirect_url="https://auth.example/interact/abc",
            continue_uri="https://auth.example/continue/1",
            continue_token="cont_tok",
        )
        assert err.is_recoverable is True


class MockResponse:
    """Minimal httpx.Response mock."""

    def __init__(self, status_code, data=None, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._data = data

    def json(self):
        if self._data is not None:
            return self._data
        raise ValueError("No JSON")


class TestParseGnapErrorResponse:
    @pytest.mark.asyncio
    async def test_parse_object_format(self):
        resp = MockResponse(400, {"error": {"code": "invalid_client", "description": "Bad key"}})
        err = await parse_gnap_error_response(resp)
        assert err.code == "invalid_client"
        assert err.description == "Bad key"
        assert err.status_code == 400

    @pytest.mark.asyncio
    async def test_parse_string_format(self):
        resp = MockResponse(403, {"error": "user_denied"})
        err = await parse_gnap_error_response(resp)
        assert err.code == "user_denied"
        assert err.status_code == 403

    @pytest.mark.asyncio
    async def test_parse_retry_after(self):
        resp = MockResponse(429, {"error": "too_fast"}, headers={"Retry-After": "5"})
        err = await parse_gnap_error_response(resp)
        assert err.retry_after == 5

    @pytest.mark.asyncio
    async def test_parse_continuation_info(self):
        resp = MockResponse(400, {
            "error": {"code": "too_fast"},
            "continue": {
                "uri": "https://auth.example/continue/1",
                "access_token": {"value": "cont_tok"},
            },
        })
        err = await parse_gnap_error_response(resp)
        assert err.continue_uri == "https://auth.example/continue/1"
        assert err.continue_token == "cont_tok"

    @pytest.mark.asyncio
    async def test_parse_non_json(self):
        class BadResponse:
            status_code = 500
            headers = {}
            def json(self):
                raise ValueError("not json")

        err = await parse_gnap_error_response(BadResponse())
        assert err.code == "unknown_error"
        assert err.status_code == 500
