"""
In-memory Token Store for GNAP tokens.
"""

from __future__ import annotations

from typing import Optional

from .types import TokenInfo


class InMemoryTokenStore:
    """
    Simple in-memory token store.

    Stores GNAP access tokens keyed by scope. Suitable for
    single-process applications. For distributed systems,
    implement a custom store backed by Redis or a database.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenInfo] = {}

    async def get(self, scope_key: str) -> Optional[TokenInfo]:
        """Retrieve a stored token by scope key."""
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
