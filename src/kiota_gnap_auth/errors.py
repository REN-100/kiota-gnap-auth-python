"""
GNAP Error Handling (RFC 9635 §3.6)

Provides structured error classes for GNAP authorization server responses,
including machine-readable error codes and recovery information.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# RFC 9635 §3.6 error codes
GNAP_ERROR_CODES = frozenset({
    "invalid_client",
    "invalid_interaction",
    "invalid_flag",
    "invalid_rotation",
    "key_rotation_not_supported",
    "need_key",
    "too_fast",
    "too_many_attempts",
    "unknown_interaction",
    "unknown_request",
    "user_denied",
    "request_denied",
    "invalid_continuation",
    "user_code_expired",
})

# Error codes that may succeed on retry
RETRYABLE_ERROR_CODES = frozenset({"too_fast", "too_many_attempts"})


class GnapError(Exception):
    """
    Structured GNAP error response (RFC 9635 §3.6).

    Attributes:
        code: Machine-readable error code
        description: Human-readable error description
        status_code: HTTP status code from the AS response
        retry_after: Seconds to wait before retrying (from Retry-After header)
        continue_uri: Continuation URI if the error is recoverable
        continue_token: Continuation access token if recoverable
    """

    def __init__(
        self,
        code: str,
        description: Optional[str] = None,
        status_code: Optional[int] = None,
        retry_after: Optional[int] = None,
        continue_uri: Optional[str] = None,
        continue_token: Optional[str] = None,
    ) -> None:
        self.code = code
        self.description = description
        self.status_code = status_code
        self.retry_after = retry_after
        self.continue_uri = continue_uri
        self.continue_token = continue_token
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        msg = f"GNAP error: {self.code}"
        if self.description:
            msg += f" — {self.description}"
        if self.status_code:
            msg += f" (HTTP {self.status_code})"
        return msg

    @property
    def is_retryable(self) -> bool:
        """Whether this error may succeed on retry."""
        return self.code in RETRYABLE_ERROR_CODES

    @property
    def is_recoverable(self) -> bool:
        """Whether the grant can be continued after this error."""
        return self.continue_uri is not None


class GnapInteractionRequiredError(GnapError):
    """
    Error indicating resource owner interaction is required.

    Thrown when the AS responds with an `interact` field but no
    access token, meaning the user must authorize via redirect
    or user_code before the grant can be continued.
    """

    def __init__(
        self,
        redirect_url: Optional[str] = None,
        user_code: Optional[str] = None,
        user_code_uri: Optional[str] = None,
        finish_nonce: Optional[str] = None,
        continue_uri: Optional[str] = None,
        continue_token: Optional[str] = None,
    ) -> None:
        self.redirect_url = redirect_url
        self.user_code = user_code
        self.user_code_uri = user_code_uri
        self.finish_nonce = finish_nonce
        super().__init__(
            code="interaction_required",
            description=self._describe(),
            continue_uri=continue_uri,
            continue_token=continue_token,
        )

    def _describe(self) -> str:
        if self.redirect_url:
            return f"Redirect user to: {self.redirect_url}"
        if self.user_code:
            return f"User code: {self.user_code}"
        return "Interaction required"


async def parse_gnap_error_response(response: Any) -> GnapError:
    """
    Parse a GNAP error response into a structured GnapError.

    Supports both formats:
    - Object: ``{"error": {"code": "...", "description": "..."}}``
    - String: ``{"error": "error_code"}``

    Args:
        response: httpx.Response object

    Returns:
        Appropriate GnapError subclass
    """
    status_code = getattr(response, "status_code", None)

    # Parse Retry-After header
    retry_after: Optional[int] = None
    headers = getattr(response, "headers", {})
    if isinstance(headers, dict):
        ra = headers.get("retry-after") or headers.get("Retry-After")
    else:
        ra = headers.get("retry-after") or headers.get("Retry-After")
    if ra:
        try:
            retry_after = int(ra)
        except (ValueError, TypeError):
            pass

    # Parse body
    try:
        data = response.json()
    except Exception:
        return GnapError(
            code="unknown_error",
            description=f"HTTP {status_code}",
            status_code=status_code,
            retry_after=retry_after,
        )

    error = data.get("error", {})

    # String format: {"error": "error_code"}
    if isinstance(error, str):
        return GnapError(
            code=error,
            status_code=status_code,
            retry_after=retry_after,
        )

    # Object format: {"error": {"code": "...", "description": "..."}}
    code = error.get("code", "unknown_error")
    description = error.get("description")

    # Check for continuation info
    continue_info = data.get("continue")
    continue_uri = None
    continue_token = None
    if continue_info:
        continue_uri = continue_info.get("uri")
        ct = continue_info.get("access_token")
        if isinstance(ct, dict):
            continue_token = ct.get("value")
        elif isinstance(ct, str):
            continue_token = ct

    return GnapError(
        code=code,
        description=description,
        status_code=status_code,
        retry_after=retry_after,
        continue_uri=continue_uri,
        continue_token=continue_token,
    )
