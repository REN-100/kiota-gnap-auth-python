"""
Typed Event Emitter for GNAP Lifecycle Observability

Provides a lightweight event system for monitoring grant lifecycle
events without coupling to specific logging/monitoring frameworks.
"""

from __future__ import annotations

from typing import Any, Callable


class GnapEventEmitter:
    """
    Event emitter for GNAP lifecycle events.

    Supported events:
        - ``token:acquired`` — New token obtained from AS
        - ``token:rotated`` — Token successfully rotated via management URI
        - ``token:rotation_failed`` — Token rotation failed, falling back to new grant
        - ``grant:interaction_required`` — AS requires RO interaction
        - ``grant:polling`` — Polling continuation URI
        - ``grant:error`` — Grant request failed

    Example::

        events = GnapEventEmitter()
        events.on("token:acquired", lambda data: print(f"Token: {data}"))
    """

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable[..., Any]]] = {}

    def on(self, event: str, callback: Callable[..., Any]) -> None:
        """Register a listener for an event."""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable[..., Any]) -> None:
        """Remove a listener for an event."""
        if event in self._listeners:
            self._listeners[event] = [
                cb for cb in self._listeners[event] if cb is not callback
            ]

    def emit(self, event: str, data: Any = None) -> None:
        """Emit an event to all registered listeners."""
        for callback in self._listeners.get(event, []):
            try:
                callback(data)
            except Exception:
                pass  # Don't let listener errors break the flow

    def clear(self) -> None:
        """Remove all listeners."""
        self._listeners.clear()
