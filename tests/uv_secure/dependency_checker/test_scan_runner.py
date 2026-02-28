from anyio import Path as APath
import pytest
from pytest_mock import MockerFixture

from uv_secure.configuration import Configuration, VulnerabilityCriteria
from uv_secure.configuration.toml_fixer import FixAppliedSummary
from uv_secure.dependency_checker.scan_runner import (
    _apply_removed_ignores_to_in_memory_configuration,
    _apply_unused_ignore_fixes,
    _apply_unused_ignore_policy_result,
    _collect_fix_targets_by_source,
    _collect_unused_ignore_package_sources,
    _collect_unused_ignore_vulnerability_sources,
    _format_config_source,
    UnusedIgnoreAnalysis,
    UnusedIgnorePolicyResult,
)
from uv_secure.dependency_checker.status import RunStatus
from uv_secure.output_models import ScanResultsOutput


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


def test_apply_unused_ignore_policy_result_prints_fix_error_for_columns(
    mocker: MockerFixture,
) -> None:
    console = mocker.Mock()
    policy_result = UnusedIgnorePolicyResult(
        status=RunStatus.RUNTIME_ERROR, fix_error_message="fix failed"
    )
    scan_results = ScanResultsOutput()

    status = _apply_unused_ignore_policy_result(
        policy_result, Configuration(), scan_results, console
    )

    assert status == RunStatus.RUNTIME_ERROR
    assert scan_results.errors == []
    console.print.assert_called_once_with("[bold red]Error:[/] fix failed")


def test_collect_fix_targets_by_source_ignores_empty_cli_overrides() -> None:
    lock_file = APath("project/uv.lock")
    config_source = APath("project/uv-secure.toml")
    config = Configuration(
        fix=True,
        vulnerability_criteria=VulnerabilityCriteria(ignore_vulnerabilities={"VULN-1"}),
        ignore_packages={"pkg-a": ()},
    )
    analysis = UnusedIgnoreAnalysis(
        unused_ignore_ids={"VULN-1"},
        unmatched_ignore_packages={"pkg-a"},
        matched_but_clean_ignore_packages=set(),
        unused_vulnerability_ignore_sources={},
        unused_package_ignore_sources={},
    )

    fix_targets = _collect_fix_targets_by_source(
        analysis, {lock_file: config}, {lock_file: config_source}, "", []
    )

    assert fix_targets == {config_source: ({"VULN-1"}, {"pkg-a"})}
