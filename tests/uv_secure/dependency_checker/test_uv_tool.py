import asyncio

import pytest
from pytest_mock import MockerFixture

from uv_secure.dependency_checker.uv_tool import detect_uv_version, extract_uv_version


def test_extract_uv_version_parses_tokens() -> None:
    assert extract_uv_version("uv dev build 0.10.0 extra") == "0.10.0"


def test_extract_uv_version_returns_none_for_invalid_string() -> None:
    assert extract_uv_version("uv-dev build") is None


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        loop = asyncio.get_running_loop()
        result_future = loop.create_future()
        result_future.set_result((self.stdout, self.stderr))
        return await result_future


@pytest.mark.asyncio
async def test_detect_uv_version_reads_stdout(mocker: MockerFixture) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"uv 1.2.3", b"", 0)

    mocker.patch(
        "uv_secure.dependency_checker.uv_tool.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await detect_uv_version() == "1.2.3"


@pytest.mark.asyncio
async def test_detect_uv_version_reads_stderr(mocker: MockerFixture) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"", b"uv 2.0.1", 0)

    mocker.patch(
        "uv_secure.dependency_checker.uv_tool.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await detect_uv_version() == "2.0.1"


@pytest.mark.asyncio
async def test_detect_uv_version_handles_non_zero_exit(mocker: MockerFixture) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"uv 3.0.0", b"", 1)

    mocker.patch(
        "uv_secure.dependency_checker.uv_tool.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await detect_uv_version() is None


@pytest.mark.asyncio
async def test_detect_uv_version_handles_missing_binary(mocker: MockerFixture) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        raise FileNotFoundError

    mocker.patch(
        "uv_secure.dependency_checker.uv_tool.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await detect_uv_version() is None


@pytest.mark.asyncio
async def test_detect_uv_version_returns_none_when_output_empty(
    mocker: MockerFixture,
) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"", b"", 0)

    mocker.patch(
        "uv_secure.dependency_checker.uv_tool.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await detect_uv_version() is None
