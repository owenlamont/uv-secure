import asyncio
from collections.abc import AsyncGenerator, Callable
from contextlib import closing
from pathlib import Path
import sqlite3
import time
from typing import Any

from anyio import Path as APath
import orjson
import pytest
import pytest_asyncio
from pytest_mock import MockerFixture
import stamina

from uv_secure.caching.cache_manager import CacheManager


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "cache"


@pytest_asyncio.fixture
async def cache_manager(cache_dir: Path) -> AsyncGenerator[CacheManager, None]:
    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    await cm.init()
    yield cm
    await cm.close()


@pytest.mark.asyncio
async def test_get_or_compute_fetches_and_caches_in_memory(
    cache_manager: CacheManager,
) -> None:
    calls = 0

    async def fetch() -> dict[str, str]:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return {"foo": "bar"}

    result1 = await cache_manager.get_or_compute("key1", fetch)
    assert result1 == {"foo": "bar"}
    assert calls == 1

    # Should hit memory cache
    result2 = await cache_manager.get_or_compute("key1", fetch)
    assert result2 == {"foo": "bar"}
    assert calls == 1


@pytest.mark.asyncio
async def test_get_or_compute_persists_to_sqlite(
    cache_manager: CacheManager, cache_dir: Path
) -> None:
    async def fetch() -> dict[str, str]:
        await asyncio.sleep(0)
        return {"data": "persistent"}

    await cache_manager.get_or_compute("persist", fetch)

    db_path = cache_dir / "cache.db"
    assert db_path.exists()

    with closing(sqlite3.connect(str(db_path))) as conn:
        row = conn.execute("SELECT data FROM cache WHERE key = 'persist'").fetchone()
        assert row is not None
        assert orjson.loads(row[0]) == {"data": "persistent"}


@pytest.mark.asyncio
async def test_get_or_compute_loads_from_sqlite(cache_dir: Path) -> None:
    # Pre-populate SQLite
    db_path = cache_dir / "cache.db"
    await APath(cache_dir).mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute(
            "CREATE TABLE cache (key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
        )
        conn.execute(
            "INSERT INTO cache (key, data, expires_at) VALUES (?, ?, ?)",
            ("db_hit", orjson.dumps({"from": "db"}), time.time() + 100),
        )
        conn.commit()

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    await cm.init()
    try:
        calls = 0

        async def fetch() -> dict[str, str]:  # pragma: no cover
            nonlocal calls
            calls += 1
            await asyncio.sleep(0)
            return {"from": "fetch"}

        result = await cm.get_or_compute("db_hit", fetch)
        assert result == {"from": "db"}
        assert calls == 0

        # Verify it populated memory
        assert cm.memory_cache["db_hit"].data == {"from": "db"}
    finally:
        await cm.close()


@pytest.mark.asyncio
async def test_init_recreates_db_on_schema_mismatch(cache_dir: Path) -> None:
    db_path = cache_dir / "cache.db"
    await APath(cache_dir).mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute("CREATE TABLE cache (key TEXT PRIMARY KEY, data BLOB)")
        conn.execute(
            "INSERT INTO cache (key, data) VALUES (?, ?)",
            ("old", orjson.dumps({"from": "old"})),
        )
        conn.commit()

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    await cm.init()
    try:
        with closing(sqlite3.connect(str(db_path))) as conn:
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(cache)").fetchall()
            }
            assert columns == {"key", "data", "expires_at"}
            old_row = conn.execute(
                "SELECT data FROM cache WHERE key = 'old'"
            ).fetchone()
            assert old_row is None

        await cm.get_or_compute("fresh", lambda: asyncio.sleep(0, result="ok"))
        await cm.init()
        with closing(sqlite3.connect(str(db_path))) as conn:
            fresh_row = conn.execute(
                "SELECT data FROM cache WHERE key = 'fresh'"
            ).fetchone()
            assert fresh_row is not None
            assert orjson.loads(fresh_row[0]) == "ok"
    finally:
        await cm.close()


@pytest.mark.asyncio
async def test_ttl_expiry(cache_manager: CacheManager) -> None:
    cache_manager.ttl_seconds = 0.1

    calls = 0

    async def fetch() -> str:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
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
async def test_sqlite_cache_expiry(cache_dir: Path) -> None:
    # Populate expired entry
    db_path = cache_dir / "cache.db"
    await APath(cache_dir).mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute(
            "CREATE TABLE cache (key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
        )
        conn.execute(
            "INSERT INTO cache (key, data, expires_at) VALUES (?, ?, ?)",
            ("expired", orjson.dumps("old"), time.time() - 100),
        )
        conn.commit()

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    await cm.init()
    try:
        calls = 0

        async def fetch() -> str:
            nonlocal calls
            calls += 1
            await asyncio.sleep(0)
            return "new"

        result = await cm.get_or_compute("expired", fetch)
        assert result == "new"
        assert calls == 1

        # Check if old entry was replaced/updated
        with closing(sqlite3.connect(str(db_path))) as conn:
            row = conn.execute(
                "SELECT data FROM cache WHERE key = 'expired'"
            ).fetchone()
            assert row is not None
            assert orjson.loads(row[0]) == "new"
    finally:
        await cm.close()


@pytest.mark.asyncio
async def test_read_from_sqlite_corrupt_handling(cache_dir: Path) -> None:
    db_path = cache_dir / "cache.db"
    await APath(cache_dir).mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute(
            "CREATE TABLE cache (key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
        )
        # Insert invalid JSON
        conn.execute(
            "INSERT INTO cache (key, data, expires_at) VALUES (?, ?, ?)",
            ("corrupt", b"invalid json", time.time() + 100),
        )
        conn.commit()

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    await cm.init()
    try:

        async def fetch() -> str:
            await asyncio.sleep(0)
            return "fresh"

        # Should ignore corrupt entry and fetch
        result = await cm.get_or_compute("corrupt", fetch)
        assert result == "fresh"
    finally:
        await cm.close()


def test_init_db_raises_for_unhandled_sqlite_error(
    cache_dir: Path, mocker: MockerFixture
) -> None:
    def fail_connect(*args: Any, **kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    mocker.patch.object(sqlite3, "connect", fail_connect)
    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        cm._init_db_sync()


@pytest.mark.asyncio
async def test_read_row_retries_on_database_locked(
    cache_dir: Path, mocker: MockerFixture
) -> None:
    db_path = cache_dir / "cache.db"
    await APath(cache_dir).mkdir(parents=True, exist_ok=True)
    expires_at = time.time() + 100
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute(
            "CREATE TABLE cache (key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
        )
        conn.execute(
            "INSERT INTO cache (key, data, expires_at) VALUES (?, ?, ?)",
            ("db_hit", orjson.dumps({"from": "db"}), expires_at),
        )
        conn.commit()

    cm = CacheManager(cache_dir, ttl_seconds=1.0)
    await cm.init()
    real_connect: Callable[..., sqlite3.Connection] = sqlite3.connect
    calls = 0

    def flaky_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")
        return real_connect(*args, **kwargs)

    mocker.patch.object(sqlite3, "connect", flaky_connect)
    try:
        with stamina.set_testing(True, attempts=3, cap=True):
            row = cm._read_row_sync("db_hit", time.time())
        assert row is not None
        data, row_expires_at = row
        assert data == {"from": "db"}
        assert row_expires_at == pytest.approx(expires_at)
        assert calls >= 2
    finally:
        await cm.close()


def test_read_row_raises_for_non_lock_operational_error(
    cache_manager: CacheManager, mocker: MockerFixture
) -> None:
    def fail_connect(*args: Any, **kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    mocker.patch.object(sqlite3, "connect", fail_connect)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        cache_manager._read_row_sync("missing", time.time())


def test_write_row_retries_on_database_table_locked(
    cache_manager: CacheManager, cache_dir: Path, mocker: MockerFixture
) -> None:
    real_connect: Callable[..., sqlite3.Connection] = sqlite3.connect
    calls = 0

    def flaky_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database table is locked")
        return real_connect(*args, **kwargs)

    mocker.patch.object(sqlite3, "connect", flaky_connect)
    expires_at = time.time() + 100
    with stamina.set_testing(True, attempts=3, cap=True):
        cache_manager._write_row_sync("write_lock", {"ok": True}, expires_at)

    db_path = cache_dir / "cache.db"
    with closing(sqlite3.connect(str(db_path))) as conn:
        row = conn.execute("SELECT data FROM cache WHERE key = 'write_lock'").fetchone()
        assert row is not None
        assert orjson.loads(row[0]) == {"ok": True}
    assert calls >= 2


def test_write_row_raises_for_non_lock_operational_error(
    cache_manager: CacheManager, mocker: MockerFixture
) -> None:
    def fail_connect(*args: Any, **kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    mocker.patch.object(sqlite3, "connect", fail_connect)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        cache_manager._write_row_sync("write_fail", {"nope": True}, time.time())
