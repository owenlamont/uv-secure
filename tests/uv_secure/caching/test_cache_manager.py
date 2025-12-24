import asyncio
import time
from pathlib import Path
from typing import Any

from anyio import Path as APath
import pytest
import orjson

from uv_secure.caching.cache_manager import CacheManager

@pytest.fixture
def cache_dir(tmp_path: Path) -> APath:
    return APath(tmp_path / "cache")

@pytest.fixture
def cache_manager(cache_dir: APath) -> CacheManager:
    return CacheManager(cache_dir, ttl_seconds=1.0)

async def _fetch_helper(value: Any) -> Any:
    return value

@pytest.mark.asyncio
async def test_get_or_compute_fetches_and_caches_in_memory(cache_manager: CacheManager) -> None:
    calls = 0
    async def fetch() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"foo": "bar"}

    result1 = await cache_manager.get_or_compute("key1", fetch)
    assert result1 == {"foo": "bar"}
    assert calls == 1

    # Should hit memory cache
    result2 = await cache_manager.get_or_compute("key1", fetch)
    assert result2 == {"foo": "bar"}
    assert calls == 1

@pytest.mark.asyncio
async def test_get_or_compute_persists_to_disk(cache_manager: CacheManager, cache_dir: APath) -> None:
    async def fetch() -> dict[str, str]:
        return {"data": "persistent"}

    await cache_manager.get_or_compute("persist", fetch)
    
    dir_path = cache_dir / "persist"
    assert await dir_path.exists()
    assert await dir_path.is_dir()
    
    files = [p async for p in dir_path.iterdir()]
    assert len(files) == 1
    file_path = files[0]
    assert file_path.suffix == ".json"
    
    content = orjson.loads(await file_path.read_bytes())
    assert content == {"data": "persistent"}

@pytest.mark.asyncio
async def test_get_or_compute_loads_from_disk(cache_dir: APath) -> None:
    # Pre-populate disk
    dir_path = cache_dir / "disk_hit"
    await dir_path.mkdir(parents=True, exist_ok=True)
    ts = time.time()
    file_path = dir_path / f"{ts}.json"
    await file_path.write_bytes(orjson.dumps({"from": "disk"}))

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    
    calls = 0
    async def fetch() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"from": "fetch"}

    result = await cm.get_or_compute("disk_hit", fetch)
    assert result == {"from": "disk"}
    assert calls == 0
    
    # Verify it populated memory
    assert cm.memory_cache["disk_hit"].data == {"from": "disk"}

@pytest.mark.asyncio
async def test_ttl_expiry(cache_manager: CacheManager) -> None:
    cache_manager.ttl_seconds = 0.1
    
    calls = 0
    async def fetch() -> str:
        nonlocal calls
        calls += 1
        return "val"

    await cache_manager.get_or_compute("key", fetch)
    assert calls == 1
    
    # Wait for expiry
    await asyncio.sleep(0.2)
    
    # Should refetch
    await cache_manager.get_or_compute("key", fetch)
    assert calls == 2

@pytest.mark.asyncio
async def test_stampede_protection(cache_manager: CacheManager) -> None:
    calls = 0
    
    async def slow_fetch() -> str:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.1)
        return "result"

    # Launch multiple concurrent requests
    results = await asyncio.gather(
        cache_manager.get_or_compute("stampede", slow_fetch),
        cache_manager.get_or_compute("stampede", slow_fetch),
        cache_manager.get_or_compute("stampede", slow_fetch),
    )
    
    assert results == ["result", "result", "result"]
    assert calls == 1

@pytest.mark.asyncio
async def test_disk_cache_expiry(cache_dir: APath) -> None:
    # Populate expired disk entry
    dir_path = cache_dir / "expired"
    await dir_path.mkdir(parents=True, exist_ok=True)
    ts = time.time() - 100
    file_path = dir_path / f"{ts}.json"
    await file_path.write_bytes(orjson.dumps("old"))

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    
    calls = 0
    async def fetch() -> str:
        nonlocal calls
        calls += 1
        return "new"

    result = await cm.get_or_compute("expired", fetch)
    assert result == "new"
    assert calls == 1
    
    # Check if old file was deleted
    assert not await file_path.exists()

@pytest.mark.asyncio
async def test_read_from_disk_error_handling(cache_dir: APath) -> None:
    dir_path = cache_dir / "corrupt"
    await dir_path.mkdir(parents=True, exist_ok=True)
    ts = time.time()
    file_path = dir_path / f"{ts}.json"
    await file_path.write_bytes(b"invalid json")

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    
    async def fetch() -> str:
        return "fresh"

    # Should ignore corrupt file and fetch
    result = await cm.get_or_compute("corrupt", fetch)
    assert result == "fresh"

@pytest.mark.asyncio
async def test_write_to_disk_error_handling(cache_manager: CacheManager, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail_write(*args: Any, **kwargs: Any) -> None:
        raise OSError("Disk full")

    monkeypatch.setattr(APath, "write_bytes", fail_write)
    
    async def fetch() -> str:
        return "data"

    # Should not raise exception
    await cache_manager.get_or_compute("write_fail", fetch)

@pytest.mark.asyncio
async def test_reserved_filenames(cache_dir: APath, cache_manager: CacheManager) -> None:
    # Test that reserved names are sanitized
    async def fetch() -> str:
        return "data"

    await cache_manager.get_or_compute("info/CON/1.0", fetch)
    
    # Check that directory was created with sanitized name
    expected_dir = cache_dir / "info" / "CON_" / "1.0"
    assert await expected_dir.exists()
    assert await expected_dir.is_dir()
    
    # And we can read it back
    result = await cache_manager.get_or_compute("info/CON/1.0", fetch)
    assert result == "data"

@pytest.mark.asyncio
async def test_directory_cleanup_on_expiry(cache_dir: APath) -> None:
    # Create directory and expired file
    dir_path = cache_dir / "cleanup_me"
    await dir_path.mkdir(parents=True, exist_ok=True)
    ts = time.time() - 100
    file_path = dir_path / f"{ts}.json"
    await file_path.write_bytes(orjson.dumps("old"))

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    
    # Call internal _get_from_disk directly to verify cleanup without rewrite
    result = await cm._get_from_disk("cleanup_me")
    assert result is None
    
    # Directory should be gone
    assert not await dir_path.exists()