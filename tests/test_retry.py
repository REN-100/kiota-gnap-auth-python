"""
Tests for retry policy with exponential backoff.
"""

import pytest

from kiota_gnap_auth.retry import RetryPolicy, with_retry


class TestWithRetry:
    @pytest.mark.asyncio
    async def test_returns_on_first_success(self):
        async def fn():
            return "ok"

        result = await with_retry(fn)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_retries_on_exception(self):
        attempts = []

        async def fn():
            attempts.append(1)
            if len(attempts) < 3:
                raise ValueError("fail")
            return "ok"

        policy = RetryPolicy(max_attempts=3, base_delay_s=0.01, jitter=False)
        result = await with_retry(fn, policy=policy)
        assert result == "ok"
        assert len(attempts) == 3

    @pytest.mark.asyncio
    async def test_retries_based_on_predicate(self):
        attempts = []

        async def fn():
            attempts.append(1)
            return len(attempts)

        policy = RetryPolicy(max_attempts=3, base_delay_s=0.01, jitter=False)
        result = await with_retry(
            fn, policy=policy, should_retry=lambda r: r < 3
        )
        assert result == 3

    @pytest.mark.asyncio
    async def test_exhausts_retries(self):
        async def fn():
            raise ValueError("always fails")

        policy = RetryPolicy(max_attempts=2, base_delay_s=0.01, jitter=False)
        with pytest.raises(ValueError, match="always fails"):
            await with_retry(fn, policy=policy)

    @pytest.mark.asyncio
    async def test_no_retries_when_zero(self):
        attempts = []

        async def fn():
            attempts.append(1)
            raise ValueError("fail")

        policy = RetryPolicy(max_attempts=0)
        with pytest.raises(ValueError):
            await with_retry(fn, policy=policy)
        assert len(attempts) == 1

    @pytest.mark.asyncio
    async def test_returns_last_result_when_predicate_exhausted(self):
        async def fn():
            return 42

        policy = RetryPolicy(max_attempts=2, base_delay_s=0.01, jitter=False)
        result = await with_retry(
            fn, policy=policy, should_retry=lambda r: True
        )
        assert result == 42

    def test_default_policy_has_sensible_values(self):
        from kiota_gnap_auth.retry import DEFAULT_RETRY_POLICY
        assert DEFAULT_RETRY_POLICY.max_attempts == 3
        assert DEFAULT_RETRY_POLICY.base_delay_s == 1.0
        assert 429 in DEFAULT_RETRY_POLICY.retryable_statuses
        assert DEFAULT_RETRY_POLICY.jitter is True
