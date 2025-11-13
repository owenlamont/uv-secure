from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import uv_secure.package_info.package_index_downloader as pid


class DummyDep:
    def __init__(self, name: str, version: str = "1.0.0", direct: bool = True):
        self.name = name
        self.version = version
        self.direct = direct


@pytest.fixture
def dependency_factory():
    def _make(name="example_pkg", version="1.2.3", direct=True):
        return DummyDep(name=name, version=version, direct=direct)

    return _make


@pytest.fixture
def mock_http_client(mocker):
    client = SimpleNamespace()
    response = SimpleNamespace(content=b'{"ok": true}', raise_for_status=mocker.Mock())
    client.get = AsyncMock(return_value=response)
    return client


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        (pid.ProjectState.ACTIVE, "active"),
        (pid.ProjectState.ARCHIVED, "archived"),
        (pid.ProjectState.DEPRECATED, "deprecated"),
        (pid.ProjectState.QUARANTINED, "quarantined"),
    ],
    ids=["active", "archived", "deprecated", "quarantined"],
)
def test_project_state_values(member, expected):
    assert member.value == expected


@pytest.mark.parametrize(
    ("disable_cache"), [False, True], ids=["cache-enabled", "cache-disabled"]
)
def test_build_request_headers_merges_and_controls_cache(disable_cache):
    extra = {"Accept": "application/vnd.custom+json", "X-Test": "t"}
    headers = pid._build_request_headers(disable_cache, extra)

    assert "Accept" in headers
    assert "application/vnd.custom+json" in headers["Accept"]

    assert headers["X-Test"] == "t"

    cc = headers.get("Cache-Control", "")
    if disable_cache:
        assert "no-cache" in cc
        assert "no-store" in cc
    else:
        assert cc != "no-cache, no-store"


@pytest.mark.asyncio
async def test__download_package_index_builds_url_and_uses_vendor_accept(
    mocker, dependency_factory, mock_http_client
):
    dep = dependency_factory(name="Pandas", version="2.2.3")

    mocker.patch.object(pid, "canonicalize_name", return_value="pandas")

    fake_obj = object()
    spy_validate = mocker.patch.object(
        pid.PackageIndex, "model_validate_json", return_value=fake_obj
    )

    out = await pid._download_package_index(mock_http_client, dep, disable_cache=True)

    mock_http_client.get.assert_awaited_once()
    called_url = mock_http_client.get.await_args.args[0]
    assert called_url == "https://pypi.org/simple/pandas/"

    called_headers = mock_http_client.get.await_args.kwargs.get("headers", {})
    assert "application/vnd.pypi.simple.v1+json" in called_headers.get("Accept", "")

    cc = called_headers.get("Cache-Control", "")
    assert "no-cache" in cc
    assert "no-store" in cc

    spy_validate.assert_called_once_with(b'{"ok": true}')
    assert out is fake_obj


@pytest.mark.asyncio
async def test__download_package_index_propagates_http_error(
    mocker, dependency_factory, mock_http_client
):
    dep = dependency_factory(name="demo")

    mocker.patch.object(pid, "canonicalize_name", return_value="demo")
    bad_resp = SimpleNamespace(
        content=b"{}",
        raise_for_status=mocker.Mock(side_effect=RuntimeError("HTTP 500")),
    )
    mock_http_client.get = AsyncMock(return_value=bad_resp)

    with pytest.raises(RuntimeError):
        await pid._download_package_index(mock_http_client, dep, disable_cache=False)


@pytest.mark.asyncio
async def test_download_package_indexes_preserves_order_and_exceptions(
    mocker, dependency_factory
):
    deps = [
        dependency_factory(name="a"),
        dependency_factory(name="b"),
        dependency_factory(name="c"),
    ]
    good1 = object()
    boom = RuntimeError("kapow")
    good2 = object()

    stub = mocker.patch.object(
        pid, "_download_package_index", new=AsyncMock(side_effect=[good1, boom, good2])
    )

    http_client = SimpleNamespace()  # never used because we patched the leaf
    results = await pid.download_package_indexes(deps, http_client, disable_cache=True)

    assert results == [good1, boom, good2]
    # Ensure every dependency was scheduled
    assert stub.await_count == len(deps)
    # And that call order tracked deps order
    called_deps = [call.args[1] for call in stub.await_args_list]
    assert called_deps == deps
