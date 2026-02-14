import asyncio

from httpx import AsyncClient
import pytest
from pytest_mock import MockerFixture

from uv_secure.configuration import Configuration
from uv_secure.dependency_checker.tool_audit import check_global_uv_tool
from uv_secure.output_models import DependencyOutput


@pytest.mark.asyncio
async def test_check_global_uv_returns_none_when_detection_fails(
    mocker: MockerFixture,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return None

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_detect
    )

    async with AsyncClient() as client:
        result = await check_global_uv_tool(Configuration(), client, None)
    assert result is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_none_when_metadata_skipped(
    mocker: MockerFixture,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return "0.9.9"

    async def _fake_download(*_: object, **__: object) -> list[str]:
        await asyncio.sleep(0)
        return ["payload"]

    def _fake_process(*_: object, **__: object) -> None:
        return None

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_detect
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.download_packages", _fake_download
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.download_package_indexes",
        _fake_download,
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.process_package_metadata",
        _fake_process,
    )

    async with AsyncClient() as client:
        result = await check_global_uv_tool(Configuration(), client, None)
    assert result is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_none_when_no_findings(
    mocker: MockerFixture,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return "0.9.9"

    async def _fake_download(*_: object, **__: object) -> list[str]:
        await asyncio.sleep(0)
        return ["payload"]

    dependency_output = DependencyOutput(name="uv", version="0.9.9", direct=True)

    def _fake_process(*_: object, **__: object) -> DependencyOutput:
        return dependency_output

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_detect
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.download_packages", _fake_download
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.download_package_indexes",
        _fake_download,
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.process_package_metadata",
        _fake_process,
    )

    async with AsyncClient() as client:
        result = await check_global_uv_tool(Configuration(), client, None)
    assert result is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_error_output_when_metadata_errors(
    mocker: MockerFixture,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return "0.9.9"

    async def _fake_download(*_: object, **__: object) -> list[str]:
        await asyncio.sleep(0)
        return ["payload"]

    def _fake_process(*_: object, **__: object) -> str:
        return "boom"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_detect
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.download_packages", _fake_download
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.download_package_indexes",
        _fake_download,
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.process_package_metadata",
        _fake_process,
    )

    async with AsyncClient() as client:
        result = await check_global_uv_tool(Configuration(), client, None)
    assert result is not None
    assert result.file_path == "uv (global tool)"
    assert result.error == "boom"
