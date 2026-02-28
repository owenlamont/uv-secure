from anyio import Path as APath
import pytest
from pytest_mock import MockerFixture

from uv_secure.configuration import Configuration, VulnerabilityCriteria
from uv_secure.configuration.toml_fixer import FixAppliedSummary
from uv_secure.dependency_checker.scan_runner import (
    _apply_removed_ignores_to_in_memory_configuration,
    _apply_unused_ignore_fixes,
    _collect_unused_ignore_package_sources,
    _collect_unused_ignore_vulnerability_sources,
    _format_config_source,
)


def test_format_config_source_returns_default_configuration_for_missing_source() -> (
    None
):
    assert _format_config_source(None, False) == "default configuration"


def test_collect_unused_ignore_vulnerability_sources_skips_allow_unused_ignores() -> (
    None
):
    lock_file = APath("project/uv.lock")
    lock_to_config_map = {
        lock_file: Configuration(
            vulnerability_criteria=VulnerabilityCriteria(
                allow_unused_ignores=True, ignore_vulnerabilities={"VULN-1"}
            )
        )
    }

    ignore_sources = _collect_unused_ignore_vulnerability_sources(
        {"VULN-1"},
        lock_to_config_map,
        {lock_file: APath("project/uv-secure.toml")},
        None,
    )

    assert ignore_sources == {}


def test_collect_unused_ignore_vulnerability_sources_skips_non_matching_ids() -> None:
    lock_file = APath("project/uv.lock")
    lock_to_config_map = {
        lock_file: Configuration(
            vulnerability_criteria=VulnerabilityCriteria(
                ignore_vulnerabilities={"VULN-1"}
            )
        )
    }

    ignore_sources = _collect_unused_ignore_vulnerability_sources(
        {"VULN-2"},
        lock_to_config_map,
        {lock_file: APath("project/uv-secure.toml")},
        None,
    )

    assert ignore_sources == {}


def test_collect_unused_ignore_package_sources_skips_allow_unused_ignores() -> None:
    lock_file = APath("project/uv.lock")
    lock_to_config_map = {
        lock_file: Configuration(
            vulnerability_criteria=VulnerabilityCriteria(allow_unused_ignores=True),
            ignore_packages={"example-package": ()},
        )
    }

    ignore_sources = _collect_unused_ignore_package_sources(
        {"example-package"},
        lock_to_config_map,
        {lock_file: APath("project/uv-secure.toml")},
        None,
    )

    assert ignore_sources == {}


@pytest.mark.asyncio
async def test_apply_unused_ignore_fixes_handles_noop_results(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "uv_secure.dependency_checker.scan_runner.fix_unused_ignores_in_toml_config",
        return_value=FixAppliedSummary(set(), set(), False),
    )

    (
        removed_vulnerability_ids,
        removed_package_names,
        modified_files,
    ) = await _apply_unused_ignore_fixes(
        {APath("project/uv-secure.toml"): ({"VULN-999"}, {"missing-pkg"})}
    )

    assert removed_vulnerability_ids == {}
    assert removed_package_names == {}
    assert modified_files == 0


def test_apply_removed_ignores_to_in_memory_configuration_handles_none_values() -> None:
    lock_file = APath("project/uv.lock")
    config_source = APath("project/uv-secure.toml")
    config = Configuration(fix=True)
    config.vulnerability_criteria.ignore_vulnerabilities = None
    config.ignore_packages = None

    _apply_removed_ignores_to_in_memory_configuration(
        {lock_file: config},
        {lock_file: config_source},
        {config_source: {"VULN-999"}},
        {config_source: {"missing-pkg"}},
    )

    assert config.vulnerability_criteria.ignore_vulnerabilities is None
    assert config.ignore_packages is None
