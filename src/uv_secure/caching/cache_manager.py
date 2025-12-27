import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import time
from typing import Any

import orjson
import stamina


class SqliteLockedError(RuntimeError):
    """Raised when SQLite is locked or busy and should be retried."""


@dataclass
class CacheEntry:
    data: Any
    expires_at: float


class CacheManager:
    """Two-tier cache manager (Memory + SQLite) with stampede protection."""

    def __init__(self, cache_dir: Path, ttl_seconds: float):
        self.memory_cache: dict[str, CacheEntry] = {}
        self.cache_dir = cache_dir
        self.db_path = cache_dir / "cache.db"
        self.ttl_seconds = ttl_seconds
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

        # Allow multiple workers for concurrency
        # SQLite connection overhead is low, so we open/close per task to ensure safety
        # and avoid thread-local leak issues.
        self._max_workers = 4
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="uv-secure-sqlite"
        )

    async def init(self) -> None:
        """Initialize the database asynchronously."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._init_db_sync)

    def _init_db_sync(self) -> None:
        """Create the cache table if it doesn't exist (run in executor)."""
        # Ensure parent exists (this might be redundant if caller did it, but safe)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        expected_columns = {"key", "data", "expires_at"}
        with closing(sqlite3.connect(str(self.db_path), timeout=10.0)) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
            )
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(cache)").fetchall()
            }
            if columns != expected_columns:
                conn.close()
                self.db_path.unlink(missing_ok=True)
                with closing(sqlite3.connect(str(self.db_path), timeout=10.0)) as fresh:
                    fresh.execute(
                        "CREATE TABLE IF NOT EXISTS cache "
                        "(key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
                    )
                    fresh.execute("PRAGMA journal_mode=WAL")
                    fresh.execute(
                        "CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)"
                    )
                return

            # Use WAL mode for better concurrency and performance
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)"
            )

    async def _get_lock(self, key: str) -> asyncio.Lock:
        async with self._locks_lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            return self._locks[key]

    def _get_from_memory(self, key: str) -> Any | None:
        entry = self.memory_cache.get(key)
        if entry:
            if time.time() < entry.expires_at:
                return entry.data
            del self.memory_cache[key]
        return None

    async def _get_from_disk(self, key: str) -> tuple[Any, float] | None:
        loop = asyncio.get_running_loop()
        row = await loop.run_in_executor(self._executor, self._get_from_disk_sync, key)

        if row is None:
            return None

        data, expires_at = row
        return data, expires_at

    def _get_from_disk_sync(self, key: str) -> tuple[Any, float] | None:
        now = time.time()
        return self._read_row_sync(key, now)

    @stamina.retry(on=SqliteLockedError, attempts=3)
    def _read_row_sync(self, key: str, now: float) -> tuple[Any, float] | None:
        try:
            # Explicit open/close to avoid ResourceWarning
            with closing(sqlite3.connect(str(self.db_path), timeout=10.0)) as conn:
                row = conn.execute(
                    "SELECT data, expires_at FROM cache WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    return None

                data_blob, expires_at = row
                if now > expires_at:
                    conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                    conn.commit()
                    return None

                try:
                    data = orjson.loads(data_blob)
                except orjson.JSONDecodeError:
                    conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                    conn.commit()
                    return None

                return data, float(expires_at)
        except sqlite3.OperationalError as exc:
            if self._is_lock_error(exc):
                raise SqliteLockedError(str(exc)) from exc
            raise

    async def _write_to_disk(self, key: str, data: Any, expires_at: float) -> None:
        def _write() -> None:
            self._write_row_sync(key, data, expires_at)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, _write)

    @stamina.retry(on=SqliteLockedError, attempts=3)
    def _write_row_sync(self, key: str, data: Any, expires_at: float) -> None:
        try:
            data_blob = orjson.dumps(data)
            with closing(sqlite3.connect(str(self.db_path), timeout=10.0)) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cache (key, data, expires_at) "
                    "VALUES (?, ?, ?)",
                    (key, data_blob, expires_at),
                )
                conn.commit()
        except sqlite3.OperationalError as exc:
            if self._is_lock_error(exc):
                raise SqliteLockedError(str(exc)) from exc
            raise

    @staticmethod
    def _is_lock_error(exc: sqlite3.OperationalError) -> bool:
        message = str(exc).lower()
        return "database is locked" in message or "database table is locked" in message

    async def get_or_compute(
        self, key: str, coro_func: Callable[[], Awaitable[Any]]
    ) -> Any:
        """Get data from cache or compute it using the provided coroutine.

        Args:
            key: Unique cache key.
            coro_func: Coroutine function to fetch data if not cached.

        Returns:
            Any: The cached or computed data.
        """
        # 1. Check Memory
        data = self._get_from_memory(key)
        if data is not None:
            return data

        # 2. Check Disk (SQLite)
        disk_result = await self._get_from_disk(key)
        if disk_result is not None:
            data, expires_at = disk_result
            self.memory_cache[key] = CacheEntry(data=data, expires_at=expires_at)
            return data

        # 3. Compute with Stampede Protection
        lock = await self._get_lock(key)
        async with lock:
            # Double check memory (race condition handling)
            data = self._get_from_memory(key)
            if data is not None:
                return data

            # Execute fetch
            result = await coro_func()

            # Save to cache
            expires_at = time.time() + self.ttl_seconds
            self.memory_cache[key] = CacheEntry(data=result, expires_at=expires_at)

            # We await the disk write to ensure it persists
            await self._write_to_disk(key, result, expires_at)

            return result

    async def close(self) -> None:
        """Shut down the executor."""
        self._executor.shutdown(wait=True)
