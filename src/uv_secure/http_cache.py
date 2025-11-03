"""Utilities for caching HTTP responses with cashews."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cashews import Cache


class RequestCache:
    """Cache helper that stores HTTP response payloads."""

    def __init__(
        self, backend: Cache, ttl_seconds: float, *, namespace: str = "uv-secure"
    ):
        """Initialize the cache helper."""

        self._backend = backend
        self._ttl = ttl_seconds
        self._namespace = namespace

    async def get_or_set(
        self, key: str, fetcher: Callable[[], Awaitable[bytes]]
    ) -> bytes:
        """Return cached data or fetch and cache it."""

        if self._ttl <= 0:
            return await fetcher()

        namespaced_key = f"{self._namespace}:{key}"
        cached = await self._backend.get(namespaced_key)
        if isinstance(cached, bytes):
            return cached

        lock_key = f"{namespaced_key}:lock"
        async with self._backend.lock(lock_key, expire=self._ttl + 60.0):
            cached = await self._backend.get(namespaced_key)
            if isinstance(cached, bytes):
                return cached
            value = await fetcher()
            await self._backend.set(namespaced_key, value, expire=self._ttl)
            return value

    async def clear(self) -> None:
        """Clear cached entries."""

        await self._backend.clear()

    async def close(self) -> None:
        """Close the underlying backend."""

        await self._backend.close()
