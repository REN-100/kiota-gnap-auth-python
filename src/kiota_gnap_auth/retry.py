"""
Retry Policy with Exponential Backoff

Provides configurable retry logic for transient GNAP failures
(429 Too Many Requests, 5xx server errors).
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


@dataclass
class RetryPolicy:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    """Maximum number of retry attempts (0 = no retries)."""
    base_delay_s: float = 1.0
    """Base delay in seconds before first retry."""
    max_delay_s: float = 30.0
    """Maximum delay in seconds between retries."""
    jitter: bool = True
    """Add random jitter to prevent thundering herd."""
    retryable_statuses: list[int] = field(
        default_factory=lambda: [429, 500, 502, 503, 504]
    )
    """HTTP status codes that trigger retry."""


DEFAULT_RETRY_POLICY = RetryPolicy()


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    policy: RetryPolicy = DEFAULT_RETRY_POLICY,
    should_retry: Optional[Callable[[T], bool]] = None,
) -> T:
    """
    Execute an async function with configurable retry and exponential backoff.

    Args:
        fn: Async function to execute
        policy: Retry policy configuration
        should_retry: Optional predicate to check if result should trigger retry

    Returns:
        The result of the function call

    Raises:
        The last exception if all retries are exhausted
    """
    last_exception: Optional[Exception] = None
    last_result: Optional[T] = None

    for attempt in range(policy.max_attempts + 1):
        try:
            result = await fn()

            # Check if the result indicates we should retry
            if should_retry and should_retry(result) and attempt < policy.max_attempts:
                last_result = result
                delay = _compute_delay(attempt, policy)
                await asyncio.sleep(delay)
                continue

            return result

        except Exception as exc:
            last_exception = exc
            if attempt >= policy.max_attempts:
                raise
            delay = _compute_delay(attempt, policy)
            await asyncio.sleep(delay)

    # If we exhausted retries with a result (not exception), return last result
    if last_result is not None:
        return last_result

    # Should not reach here, but just in case
    if last_exception:
        raise last_exception
    raise RuntimeError("Retry exhausted with no result")


def _compute_delay(attempt: int, policy: RetryPolicy) -> float:
    """Compute delay with exponential backoff and optional jitter."""
    delay = min(policy.base_delay_s * (2 ** attempt), policy.max_delay_s)
    if policy.jitter:
        delay *= random.uniform(0.5, 1.5)
    return delay
