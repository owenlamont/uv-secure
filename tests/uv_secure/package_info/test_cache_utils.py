import asyncio
from collections.abc import Callable
from typing import Any

from cashews import Cache
import pytest

from uv_secure.package_info.cache_utils import (
    close_cache,
    coerce_cached_value,
    configure_diskcache_backend,
    get_cached_model,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(b"data", b"data", id="bytes"),
        pytest.param(bytearray(b"data"), b"data", id="bytearray"),
        pytest.param("data", b"data", id="str"),
        pytest.param(None, None, id="none"),
    ],
)
def test_coerce_cached_value(value: object | None, expected: bytes | None) -> None:
    assert coerce_cached_value(value) == expected


@pytest.mark.asyncio
async def test_get_cached_model_disable_cache_skips_store() -> None:
    cache = Cache()
    cache.setup("mem://", enable=True)

    async def fetcher() -> bytes:
        await asyncio.sleep(0)
        return b"42"

    def parser(raw: bytes) -> int:
        return int(raw.decode())

    def serializer(value: int) -> bytes:
        return str(value).encode()

    result = await get_cached_model(
        cache, "key:disabled", 10.0, True, fetcher, parser, serializer
    )

    assert result == 42
    assert await cache.get("key:disabled") is None
    await cache.close()


@pytest.mark.asyncio
async def test_get_cached_model_cache_hit_uses_cached_value() -> None:
    cache = Cache()
    cache.setup("mem://", enable=True)
    await cache.set("key:hit", b"7", expire=60)

    called = False

    async def fetcher() -> bytes:
        nonlocal called
        called = True
        await asyncio.sleep(0)
        return b"99"

    def parser(raw: bytes) -> int:
        return int(raw.decode())

    def serializer(value: int) -> bytes:
        return str(value).encode()

    result = await get_cached_model(
        cache, "key:hit", 10.0, False, fetcher, parser, serializer
    )

    assert result == 7
    assert called is False
    await cache.close()


@pytest.mark.asyncio
async def test_get_cached_model_cache_miss_sets_value() -> None:
    cache = Cache()
    cache.setup("mem://", enable=True)
    calls = 0

    async def fetcher() -> bytes:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return b"5"

    def parser(raw: bytes) -> int:
        return int(raw.decode())

    def serializer(value: int) -> bytes:
        return str(value).encode()

    result = await get_cached_model(
        cache, "key:miss", 10.0, False, fetcher, parser, serializer
    )

    assert result == 5
    assert calls == 1

    result = await get_cached_model(
        cache, "key:miss", 10.0, False, fetcher, parser, serializer
    )

    assert result == 5
    assert calls == 1
    await cache.close()


@pytest.mark.asyncio
async def test_get_cached_model_avoids_stampede() -> None:
    cache = Cache()
    cache.setup("mem://", enable=True)
    calls = 0

    async def fetcher() -> bytes:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return b"12"

    def parser(raw: bytes) -> int:
        return int(raw.decode())

    def serializer(value: int) -> bytes:
        return str(value).encode()

    results = await asyncio.gather(
        get_cached_model(
            cache, "key:stampede", 10.0, False, fetcher, parser, serializer
        ),
        get_cached_model(
            cache, "key:stampede", 10.0, False, fetcher, parser, serializer
        ),
    )

    assert results == [12, 12]
    assert calls == 1
    await cache.close()


@pytest.mark.asyncio
async def test_configure_diskcache_backend_noop_for_memory_backend() -> None:
    cache = Cache()
    cache.setup("mem://", enable=True)

    configure_diskcache_backend(cache)

    backends = getattr(cache, "_backends", {}).values()
    assert all(getattr(backend, "_executor", None) is None for backend in backends)
    await cache.close()


@pytest.mark.asyncio
async def test_configure_diskcache_backend_sets_executor(tmp_path: Any) -> None:
    cache = Cache()
    cache.setup("disk://", directory=str(tmp_path), shards=0)

    configure_diskcache_backend(cache)

    backends = getattr(cache, "_backends", {}).values()
    disk_backend = next(iter(backends))
    assert getattr(disk_backend, "_executor", None) is not None

    async def call_run_in_executor() -> None:
        run = disk_backend._run_in_executor
        await run(lambda: None)

    await call_run_in_executor()
    await close_cache(cache)


@pytest.mark.asyncio
async def test_configure_diskcache_backend_preserves_existing_executor(
    tmp_path: Any,
) -> None:
    cache = Cache()
    cache.setup("disk://", directory=str(tmp_path), shards=0)

    configure_diskcache_backend(cache)
    backends = getattr(cache, "_backends", {}).values()
    disk_backend = next(iter(backends))
    original_executor = disk_backend._executor

    configure_diskcache_backend(cache)

    assert disk_backend._executor is original_executor
    await close_cache(cache)


@pytest.mark.asyncio
async def test_close_cache_skips_missing_close_method() -> None:
    cache = Cache()
    cache.setup("mem://", enable=True)
    backends = getattr(cache, "_backends", {}).values()
    backend = next(iter(backends))

    async def run_in_executor(_call: Callable[..., Any], *_args: Any) -> None:
        await asyncio.sleep(0)
        return

    backend._run_in_executor = run_in_executor
    backend._cache = object()

    await close_cache(cache)
