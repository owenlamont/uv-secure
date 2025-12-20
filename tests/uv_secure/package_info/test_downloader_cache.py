import asyncio
from datetime import timedelta
import json
from typing import Any
from unittest.mock import MagicMock

import httpx
from httpx import AsyncClient
import pytest
from pytest_httpx import HTTPXMock

from uv_secure.package_info.cache import cache
from uv_secure.package_info.dependency_file_parser import Dependency
from uv_secure.package_info.package_index_downloader import (
    _download_package_index,
    PackageIndex,
)
from uv_secure.package_info.package_info_downloader import (
    _download_package,
    PackageInfo,
)


@pytest.mark.asyncio
async def test_download_package_cache_logic(httpx_mock: HTTPXMock) -> None:
    cache.setup("mem://")
    await cache.clear()

    # Verify cache works
    await cache.set("test", "value")
    assert await cache.get("test") == "value"
    await cache.clear()

    dependency = Dependency(name="test-pkg", version="1.0.0")
    url = "https://pypi.org/pypi/test-pkg/1.0.0/json"

    package_data = {
        "info": {
            "name": "test-pkg",
            "version": "1.0.0",
            "yanked": False,
            "release_url": "",
            "summary": "",
            "description": "",
            "classifiers": [],
            "downloads": {},
        },
        "last_serial": 1,
        "urls": [],
        "vulnerabilities": [],
    }

    httpx_mock.add_response(url=url, json=package_data)

    async with AsyncClient() as client:
        # 1. Cache miss, fetch and set
        res1 = await _download_package(client, dependency, False, timedelta(seconds=60))
        assert isinstance(res1, PackageInfo)
        assert res1.info.name == "test-pkg"

        # 2. Cache hit (early return)
        # We don't add another response, so if it tries to fetch, httpx_mock will fail
        res2 = await _download_package(client, dependency, False, timedelta(seconds=60))
        assert res2.info.name == "test-pkg"
        assert res2.info.version == res1.info.version

        # 3. Disable cache bypasses cache
        httpx_mock.add_response(url=url, json=package_data)
        res3 = await _download_package(client, dependency, True, timedelta(seconds=60))
        assert isinstance(res3, PackageInfo)
        # Note: res3 is a new object because it was re-parsed from JSON


@pytest.mark.asyncio
async def test_download_package_index_cache_logic(httpx_mock: HTTPXMock) -> None:
    cache.setup("mem://")
    await cache.clear()

    dependency = Dependency(name="test-pkg", version="1.0.0")
    url = "https://pypi.org/simple/test-pkg/"

    index_data = {"name": "test-pkg", "project-status": {"status": "active"}}

    httpx_mock.add_response(url=url, json=index_data)

    async with AsyncClient() as client:
        # 1. Cache miss
        res1 = await _download_package_index(
            client, dependency, False, timedelta(seconds=60)
        )
        assert isinstance(res1, PackageIndex)

        # 2. Cache hit
        res2 = await _download_package_index(
            client, dependency, False, timedelta(seconds=60)
        )
        assert res2.name == "test-pkg"

        # 3. Disable cache
        httpx_mock.add_response(url=url, json=index_data)
        res3 = await _download_package_index(
            client, dependency, True, timedelta(seconds=60)
        )
        assert isinstance(res3, PackageIndex)


@pytest.mark.asyncio
async def test_download_package_concurrent_lock(httpx_mock: HTTPXMock) -> None:
    cache.setup("mem://")
    await cache.clear()

    dependency = Dependency(name="concurrent-pkg", version="1.0.0")
    url = "https://pypi.org/pypi/concurrent-pkg/1.0.0/json"

    package_data = {
        "info": {
            "name": "concurrent-pkg",
            "version": "1.0.0",
            "yanked": False,
            "release_url": "",
            "summary": "",
            "description": "",
            "classifiers": [],
            "downloads": {},
        },
        "last_serial": 1,
        "urls": [],
        "vulnerabilities": [],
    }

    call_count = 0

    async def slow_response(request: Any) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.2)
        return httpx.Response(200, content=json.dumps(package_data).encode())

    httpx_mock.add_callback(slow_response, url=url)

    async with AsyncClient() as client:
        # Start both concurrently.
        # One will enter lock and call slow_response.
        # The other will wait for lock.
        # When first finishes, it sets cache and releases lock.
        # Second one enters lock, hits cache, and returns.
        results = await asyncio.gather(
            _download_package(client, dependency, False, timedelta(seconds=60)),
            _download_package(client, dependency, False, timedelta(seconds=60)),
        )

        assert isinstance(results[0], PackageInfo)
        assert isinstance(results[1], PackageInfo)
        assert results[0] == results[1]
        assert call_count == 1  # IMPORTANT: only one HTTP call made


@pytest.mark.asyncio
async def test_download_package_index_concurrent_lock(httpx_mock: HTTPXMock) -> None:
    cache.setup("mem://")
    await cache.clear()

    dependency = Dependency(name="concurrent-pkg", version="1.0.0")
    url = "https://pypi.org/simple/concurrent-pkg/"

    index_data = {"name": "concurrent-pkg", "project-status": {"status": "active"}}

    call_count = 0

    async def slow_response(request: Any) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.2)
        return httpx.Response(200, content=json.dumps(index_data).encode())

    httpx_mock.add_callback(slow_response, url=url)

    async with AsyncClient() as client:
        results = await asyncio.gather(
            _download_package_index(client, dependency, False, timedelta(seconds=60)),
            _download_package_index(client, dependency, False, timedelta(seconds=60)),
        )

        assert isinstance(results[0], PackageIndex)
        assert isinstance(results[1], PackageIndex)
        assert results[0] == results[1]
        assert call_count == 1


@pytest.mark.asyncio
async def test_download_package_type_error(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache.setup("mem://")
    await cache.clear()

    dependency = Dependency(name="error-pkg", version="1.0.0")

    mock_obj = MagicMock()
    # It must allow setting direct_dependency but not be PackageInfo instance
    monkeypatch.setattr(PackageInfo, "model_validate_json", lambda x: mock_obj)

    httpx_mock.add_response(url="https://pypi.org/pypi/error-pkg/1.0.0/json", json={})

    async with AsyncClient() as client:
        with pytest.raises(TypeError, match="Fetch failed to return PackageInfo"):
            await _download_package(client, dependency, False, timedelta(seconds=60))


@pytest.mark.asyncio
async def test_download_package_index_type_error(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache.setup("mem://")
    await cache.clear()

    dependency = Dependency(name="error-pkg", version="1.0.0")

    mock_obj = MagicMock()
    monkeypatch.setattr(PackageIndex, "model_validate_json", lambda x: mock_obj)

    httpx_mock.add_response(url="https://pypi.org/simple/error-pkg/", json={})

    async with AsyncClient() as client:
        with pytest.raises(TypeError, match="Fetch failed to return PackageIndex"):
            await _download_package_index(
                client, dependency, False, timedelta(seconds=60)
            )
