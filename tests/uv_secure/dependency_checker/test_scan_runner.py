from anyio import Path as APath

from uv_secure.configuration import Configuration, VulnerabilityCriteria
from uv_secure.dependency_checker.scan_runner import (
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
