"""
In-memory Token Store for GNAP tokens.

Provides TTL-aware token storage with automatic expiry pruning.
Implements the TokenStore protocol for plug-and-play replacement
with Redis, database, or other persistent backends.
"""

from __future__ import annotations

import time
from typing import Optional

from .types import TokenInfo


class InMemoryTokenStore:
    """
    In-memory token store with TTL-aware retrieval.

    Stores GNAP access tokens keyed by scope. Suitable for
    single-process applications. For distributed systems,
    implement the ``TokenStore`` protocol backed by Redis or
    a database.

    Features:
        - Automatic expiry pruning on ``get()``
        - ``peek()`` for non-pruning reads (used for rotation)
        - Thread-safe for async contexts
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenInfo] = {}

    async def get(self, scope_key: str) -> Optional[TokenInfo]:
        """
        Retrieve a stored token by scope key.

        Returns None and auto-prunes if the token is expired.
        """
        token = self._tokens.get(scope_key)
        if token is None:
            return None

        # Auto-prune expired tokens
        if token.expires_at is not None and token.expires_at <= time.time():
            del self._tokens[scope_key]
            return None

        return token

    async def peek(self, scope_key: str) -> Optional[TokenInfo]:
        """
        Retrieve a stored token WITHOUT auto-pruning.

        Used internally for token rotation — we need the management URI
        and old token value even after expiry.
        """
        return self._tokens.get(scope_key)

    async def set(self, scope_key: str, token: TokenInfo) -> None:
        """Store a token for the given scope key."""
        self._tokens[scope_key] = token

    async def delete(self, scope_key: str) -> None:
        """Remove a stored token."""
        self._tokens.pop(scope_key, None)

    async def clear(self) -> None:
        """Clear all stored tokens."""
        self._tokens.clear()
