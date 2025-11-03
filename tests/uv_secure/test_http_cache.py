import asyncio
from collections.abc import AsyncIterator

from cashews import Cache
import pytest
import pytest_asyncio

from uv_secure.http_cache import RequestCache


@pytest_asyncio.fixture
async def memory_cache() -> AsyncIterator[Cache]:
    cache = Cache()
    cache.setup("mem://")
    await cache.init()
    try:
        yield cache
    finally:
        await cache.clear()
        await cache.close()


@pytest.mark.asyncio
async def test_request_cache_fetches_when_ttl_non_positive(memory_cache: Cache) -> None:
    request_cache = RequestCache(memory_cache, ttl_seconds=0)

    call_count = 0

    async def fetch() -> bytes:
        nonlocal call_count
        call_count += 1
        return b"payload"

    result = await request_cache.get_or_set("key", fetch)

    assert result == b"payload"
    assert call_count == 1


@pytest.mark.asyncio
async def test_request_cache_reuses_value_during_concurrent_calls(
    memory_cache: Cache,
) -> None:
    request_cache = RequestCache(memory_cache, ttl_seconds=10)

    async def fetch() -> bytes:
        await asyncio.sleep(0)
        return b"shared"

    async def worker() -> bytes:
        return await request_cache.get_or_set("key", fetch)

    first, second = await asyncio.gather(worker(), worker())

    assert first == b"shared"
    assert second == b"shared"


@pytest.mark.asyncio
async def test_request_cache_clear_removes_cached_entries(memory_cache: Cache) -> None:
    request_cache = RequestCache(memory_cache, ttl_seconds=10)

    async def fetch() -> bytes:
        return b"cached"

    await request_cache.get_or_set("key", fetch)
    await request_cache.clear()

    namespaced_key = "uv-secure:key"
    assert await memory_cache.get(namespaced_key) is None


@pytest.mark.asyncio
async def test_request_cache_close_closes_backend() -> None:
    cache = Cache()
    cache.setup("mem://")
    await cache.init()
    request_cache = RequestCache(cache, ttl_seconds=10)

    assert cache.is_init

    await request_cache.close()

    assert not cache.is_init
