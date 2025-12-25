import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
import types
from typing import Any, TypeVar

from cashews import Cache


ParsedModel = TypeVar("ParsedModel")


def coerce_cached_value(cached_value: object | None) -> bytes | None:
    """Coerce cached values into bytes if possible.

    Returns:
        bytes | None: Cached value as bytes, if possible.
    """
    if isinstance(cached_value, bytes):
        return cached_value
    if isinstance(cached_value, bytearray):
        return bytes(cached_value)
    if isinstance(cached_value, str):
        return cached_value.encode()
    return None


def configure_diskcache_backend(cache: Cache) -> None:
    """Ensure diskcache backend uses a single dedicated executor thread."""
    backends = getattr(cache, "_backends", {}).values()
    for backend in backends:
        if backend.__class__.__module__ != "cashews.backends.diskcache":
            continue
        if getattr(backend, "_executor", None) is None:
            # cashews' diskcache backend uses run_in_executor(None, ...) which can
            # hop across multiple thread-pool threads; diskcache then creates one
            # SQLite connection per thread. Those thread-local connections aren't
            # easily closed from the main thread, which triggers ResourceWarnings
            # under pytest. Pinning diskcache work to a single dedicated executor
            # thread keeps a single connection that we can close deterministically.
            executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="uv-secure-diskcache"
            )
            backend._executor = executor

            async def _run_in_executor(
                self: Any, call: Callable[..., Any], *args: Any
            ) -> Any:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(self._executor, call, *args)

            backend._run_in_executor = types.MethodType(_run_in_executor, backend)
        break


async def get_cached_model(
    cache: Cache,
    cache_key: str,
    cache_ttl_seconds: float,
    disable_cache: bool,
    fetcher: Callable[[], Awaitable[bytes]],
    parser: Callable[[bytes], ParsedModel],
    serializer: Callable[[ParsedModel], bytes],
) -> ParsedModel:
    """Fetch a parsed model with cache + stampede protection.

    Returns:
        ParsedModel: Parsed response model.
    """
    if disable_cache:
        response_content = await fetcher()
        return parser(response_content)

    cached_value = await cache.get(cache_key)
    cached_bytes = coerce_cached_value(cached_value)
    if cached_bytes is not None:
        return parser(cached_bytes)

    lock_ttl_seconds = max(1, min(30, int(cache_ttl_seconds)))
    lock_key = f"{cache_key}:lock"
    async with cache.lock(lock_key, expire=lock_ttl_seconds):
        cached_value = await cache.get(cache_key)
        cached_bytes = coerce_cached_value(cached_value)
        if cached_bytes is not None:
            return parser(cached_bytes)

        response_content = await fetcher()
        model = parser(response_content)
        await cache.set(cache_key, serializer(model), expire=cache_ttl_seconds)
        return model


async def close_cache(cache: Cache) -> None:
    """Close cache backends, including executor-thread connections when needed."""
    backends = getattr(cache, "_backends", {}).values()
    for backend in backends:
        run_in_executor = getattr(backend, "_run_in_executor", None)
        backend_cache = getattr(backend, "_cache", None)
        if callable(run_in_executor) and backend_cache is not None:
            close = getattr(backend_cache, "close", None)
            if callable(close):
                await run_in_executor(close)
        executor = getattr(backend, "_executor", None)
        if isinstance(executor, ThreadPoolExecutor):
            executor.shutdown(wait=True)
    await cache.close()
