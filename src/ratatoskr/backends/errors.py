"""Errors whose message is safe to show to the MCP client (no DSN, host or password)."""

from __future__ import annotations


class BackendError(Exception):
    """Base class: ``str(error)`` is shown to the user as-is."""


class InvalidRequestError(BackendError):
    """The tool arguments were rejected before reaching the backend."""


class BackendQueryError(BackendError):
    """The backend rejected the request (e.g. a PostgreSQL error)."""


class BackendTimeoutError(BackendError):
    """The backend or the client-side deadline cancelled the request."""


class BackendUnavailableError(BackendError):
    """The backend could not be opened; the registry retries at most every 10 seconds."""
