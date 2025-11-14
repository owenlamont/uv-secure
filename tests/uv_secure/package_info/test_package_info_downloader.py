import datetime
from unittest.mock import Mock

import httpx
import pytest

from uv_secure.package_info.package_info_downloader import (
    _build_request_headers,
    _download_package,
    canonicalize_name,
    Dependency,
    download_packages,
    Info,
    PackageInfo,
    Url,
    Vulnerability,
)


@pytest.fixture
def dependency_factory():
    def _make(name: str, version: str, direct: bool = True):
        return Dependency(name=name, version=version, direct=direct)

    return _make


@pytest.fixture
def mock_https_client(mocker):
    return mocker.AsyncMock()


@pytest.fixture
def sample_json_bytes():
    return b'{"name": "requests", "version": "2.32.0"}'


@pytest.fixture
def base_kwargs(mocker):
    mock_info_object = mocker.patch.object(Info, autospec=True)
    mock_url_object = mocker.patch.object(Url, autospec=True)
    mock_vulnerability_object = mocker.patch.object(Vulnerability, autospec=True)
    return {
        "info": mock_info_object,
        "last_serial": 1,
        "urls": [mock_url_object],
        "vulnerability": [mock_vulnerability_object],
    }


@pytest.fixture
def fixed_now_time():
    return datetime.datetime.now()


@pytest.mark.parametrize(
    ("name", "canonical_name"),
    [
        pytest.param("", "", id="testing_empty_string"),
        pytest.param("test_.string", "test-string", id="canonicalizes_regular_string"),
        pytest.param("TEST.STRING", "test-string", id="changes_to_lowercase"),
        pytest.param(
            "test._._._string", "test-string", id="catches_consecutive_separators"
        ),
    ],
)
def test_canonicalize_name_valid_inputs(name, canonical_name):
    result = canonicalize_name(name)
    assert result == canonical_name


@pytest.mark.parametrize(
    ("test_name", "exception"),
    [
        pytest.param(None, TypeError, id="catches_NoneType_value"),
        pytest.param(123, TypeError, id="catches_inat_value"),
        pytest.param([], TypeError, id="catches_list_value"),
    ],
)
def test_canonicalize_name_typeerror_exceptions(test_name, exception):
    with pytest.raises(exception):
        canonicalize_name(test_name)


@pytest.mark.parametrize(
    ("disable_cache", "base_headers", "expected_headers"),
    [
        pytest.param(
            True,
            {"test_key": "test_value"},
            {"test_key": "test_value", "Cache-Control": "no-cache, no-store"},
            id="adds_cache_control_when_missing",
        ),
        pytest.param(
            True,
            {"test_key": "test_value", "Cache-Control": "no-cache, no-store"},
            {"test_key": "test_value", "Cache-Control": "no-cache, no-store"},
            id="preserves_existing_cache_control",
        ),
        pytest.param(
            True,
            None,
            {
                "Cache-Control": "no-cache, no-store",
            },
            id="builds_when_no_base_headers",
        ),
        pytest.param(
            False,
            {"test_key": "test_value"},
            {
                "test_key": "test_value",
            },
            id="returns_base_headers_when_disable_cache_is_false",
        ),
        pytest.param(False, None, None, id="returns_none_when_base_headers_is_none"),
    ],
)
def test_build_request_headers_disable_cache(
    disable_cache, base_headers, expected_headers
):
    result = _build_request_headers(
        disable_cache=disable_cache, base_headers=base_headers
    )
    assert result == expected_headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("disable_cache", "status_code", "expected_exception", "url", "name", "version"),
    [
        pytest.param(
            True,
            200,
            None,
            "https://pypi.org/pypi/test-package-one/1.0.0/json",
            "test-package-one",
            "1.0.0",
            id="cache_disabled_success",
        ),
        pytest.param(
            False,
            200,
            None,
            "https://pypi.org/pypi/test-package-two/2.0.0/json",
            "test-package-two",
            "2.0.0",
            id="cache_enabled_success",
        ),
        pytest.param(
            True,
            404,
            httpx.HTTPStatusError,
            "https://pypi.org/pypi/test-package-three/3.0.0/json",
            "test-package-three",
            "3.0.0",
            id="cache_disabled_404_error",
        ),
    ],
)
async def test_download_package_three_params(
    mocker,
    mock_https_client,
    dependency_factory,
    disable_cache,
    status_code,
    expected_exception,
    url,
    name,
    version,
):
    dep = dependency_factory(name=name, version=version)

    response = httpx.Response(
        status_code, content=b"{}", request=httpx.Request("GET", url)
    )
    mock_https_client.get.return_value = response

    fake_pkg = Mock(spec=PackageInfo)
    mocker.patch.object(PackageInfo, "model_validate_json", return_value=fake_pkg)

    if expected_exception:
        with pytest.raises(expected_exception):
            await _download_package(mock_https_client, dep, disable_cache)
    else:
        result = await _download_package(mock_https_client, dep, disable_cache)
        assert result is fake_pkg


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mock_results", "expected_types", "expected_count"),
    [
        pytest.param(
            [Mock(spec=PackageInfo), Mock(spec=PackageInfo)],
            [PackageInfo, PackageInfo],
            2,
            id="all_success",
        ),
        pytest.param(
            [RuntimeError("Boom"), Mock(spec=PackageInfo)],
            [RuntimeError, PackageInfo],
            2,
            id="one_fails_one_success",
        ),
        pytest.param(
            [RuntimeError("Fail1"), RuntimeError("Fail2")],
            [RuntimeError, RuntimeError],
            2,
            id="all_fail",
        ),
    ],
)
async def test_download_packages(
    mocker,
    dependency_factory,
    mock_https_client,
    mock_results,
    expected_types,
    expected_count,
):
    deps = [
        dependency_factory(name="pkg1", version="1.0.0"),
        dependency_factory(name="pkg2", version="2.0.0"),
    ]

    mock_download = mocker.patch(
        "uv_secure.package_info.package_info_downloader._download_package",
        side_effect=mock_results,
    )

    results = await download_packages(deps, mock_https_client, disable_cache=True)

    assert len(results) == expected_count
    for result, expected_type in zip(results, expected_types, strict=False):
        assert isinstance(result, expected_type)
    assert mock_download.await_count == len(deps)
