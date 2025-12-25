import asyncio
from collections.abc import Awaitable, Callable
import contextlib
from dataclasses import dataclass
import operator
import sys
import time
from typing import Any, TypeVar

from anyio import Path as APath
import orjson


T = TypeVar("T")

# Reserved filenames on Windows that cannot be used as directory or file names
# regardless of extension.
RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


@dataclass
class CacheEntry:
    data: Any
    expires_at: float


class CacheManager:
    """Two-tier cache manager (Memory + Disk) with stampede protection."""

    def __init__(self, cache_dir: APath, ttl_seconds: float):
        self.memory_cache: dict[str, CacheEntry] = {}
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

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

    def _resolve_path(self, key: str) -> APath:
        """Resolve a cache key to a safe directory path.

        Args:
            key: Cache key using forward slashes.

        Returns:
            APath: Safe directory path.
        """
        parts = key.split("/")
        safe_parts = []
        for part in parts:
            # Handle reserved names by appending an underscore
            if part.upper() in RESERVED_NAMES:
                safe_parts.append(f"{part}_")
            else:
                safe_parts.append(part)
        return self.cache_dir.joinpath(*safe_parts)

    async def _get_from_disk(self, key: str) -> tuple[Any, float] | None:
        dir_path = self._resolve_path(key)
        if not await dir_path.is_dir():
            return None

        candidates: list[tuple[float, APath]] = []
        now = time.time()

        async for file_path in dir_path.iterdir():
            if file_path.suffix != ".json":
                continue
            try:
                ts = float(file_path.stem)
            except ValueError:
                continue

            if now - ts > self.ttl_seconds:
                with contextlib.suppress(OSError):
                    await file_path.unlink()
                continue

            candidates.append((ts, file_path))

        if not candidates:
            with contextlib.suppress(OSError):
                await dir_path.rmdir()
            return None

        # Sort by timestamp descending (newest first)
        candidates.sort(key=operator.itemgetter(0), reverse=True)

        best_ts, best_path = candidates[0]

        # Cleanup superseded files
        for _, path in candidates[1:]:
            with contextlib.suppress(OSError):
                await path.unlink()

        try:
            content = await best_path.read_bytes()
            data = orjson.loads(content)
            return data, best_ts + self.ttl_seconds
        except Exception as e:
            print(f"Failed to read cache {best_path}: {e}", file=sys.stderr)
            return None

    async def _write_to_disk(self, key: str, data: Any) -> None:
        dir_path = self._resolve_path(key)
        try:
            await dir_path.mkdir(parents=True, exist_ok=True)
            ts = time.time()
            file_path = dir_path / f"{ts}.json"
            content = orjson.dumps(data)
            await file_path.write_bytes(content)
        except Exception as e:
            print(f"Failed to write cache file {dir_path}: {e}", file=sys.stderr)

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

        # 2. Check Disk
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
            await self._write_to_disk(key, result)

            return result
