import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, TypeVar

import orjson


T = TypeVar("T")


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
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, data BLOB, expires_at REAL)"
            )
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
        def _get() -> tuple[Any, float] | None:
            now = time.time()
            try:
                with sqlite3.connect(str(self.db_path), timeout=10.0) as conn:
                    cursor = conn.execute(
                        "SELECT data, expires_at FROM cache WHERE key = ?", (key,)
                    )
                    row = cursor.fetchone()

                    if row:
                        _data_blob, expires_at = row
                        # Lazy expiry check
                        if now > expires_at:
                            conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                            conn.commit()
                            return None
                        # mypy doesn't know row structure from sqlite3
                        return row  # type: ignore[no-any-return]
                    return None
            except sqlite3.Error as e:
                print(f"SQLite error reading key {key}: {e}", file=sys.stderr)
                return None

        loop = asyncio.get_running_loop()
        row = await loop.run_in_executor(self._executor, _get)

        if not row:
            return None

        if not isinstance(row, tuple) or len(row) != 2:
            return None

        data_blob, expires_at = row
        try:
            data = orjson.loads(data_blob)
            return data, float(expires_at)
        except Exception as e:
            print(f"Failed to load cache for key {key}: {e}", file=sys.stderr)
            return None

    async def _write_to_disk(self, key: str, data: Any, expires_at: float) -> None:
        def _write() -> None:
            try:
                data_blob = orjson.dumps(data)
                with sqlite3.connect(str(self.db_path), timeout=10.0) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO cache (key, data, expires_at) "
                        "VALUES (?, ?, ?)",
                        (key, data_blob, expires_at),
                    )
                    conn.commit()
            except sqlite3.Error as e:
                print(f"SQLite error writing key {key}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Failed to write cache for key {key}: {e}", file=sys.stderr)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, _write)

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
