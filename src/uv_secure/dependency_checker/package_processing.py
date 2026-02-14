from functools import cache

from packaging.specifiers import SpecifierSet

from uv_secure.configuration import Configuration
from uv_secure.dependency_checker.vulnerability_filter import filter_vulnerabilities
from uv_secure.output_models import (
    DependencyOutput,
    MaintenanceIssueOutput,
    VulnerabilityOutput,
)
from uv_secure.package_info import (
    PackageIndex,
    PackageInfo,
    ProjectState,
    Vulnerability,
)


@cache
def _get_specifier_sets(specifiers: tuple[str, ...]) -> tuple[SpecifierSet, ...]:
    """Convert string specifiers into cached ``SpecifierSet`` instances.

    Returns:
        tuple[SpecifierSet, ...]: Parsed specifier instances.
    """
    return tuple(SpecifierSet(spec) for spec in specifiers)


def _convert_vulnerability_to_output(vuln: Vulnerability) -> VulnerabilityOutput:
    return VulnerabilityOutput(
        id=vuln.id,
        details=vuln.details,
        severity=vuln.severity if isinstance(vuln.severity, str) else None,
        severity_source_link=vuln.severity_source_link,
        fix_versions=vuln.fixed_in,
        aliases=vuln.aliases,
        link=vuln.link,
    )


def _convert_maintenance_to_output(
    package_info: PackageInfo, package_index: PackageIndex
) -> MaintenanceIssueOutput | None:
    age_days = package_info.age.total_seconds() / 86400.0 if package_info.age else None
    return MaintenanceIssueOutput(
        yanked=package_info.info.yanked,
        yanked_reason=package_info.info.yanked_reason,
        age_days=age_days,
        status=package_index.status.value,
        status_reason=package_index.project_status.reason,
    )


def _should_skip_package(
    package: PackageInfo,
    ignore_packages: dict[str, tuple[SpecifierSet, ...]],
    used_ignore_packages: set[str],
) -> bool:
    if package.info.name not in ignore_packages:
        return False

    specifiers = ignore_packages[package.info.name]
    should_skip = len(specifiers) == 0 or any(
        specifier.contains(package.info.version) for specifier in specifiers
    )
    if should_skip:
        used_ignore_packages.add(package.info.name)
    return should_skip


def _should_check_vulnerabilities(package: PackageInfo, config: Configuration) -> bool:
    return (
        package.direct_dependency is not False
        or not config.vulnerability_criteria.check_direct_dependencies_only
    )


def _should_check_maintenance_issues(
    package_info: PackageInfo, config: Configuration
) -> bool:
    return (
        package_info.direct_dependency is not False
        or not config.maintainability_criteria.check_direct_dependencies_only
    )


def _has_maintenance_issues(
    package_index: PackageIndex, package_info: PackageInfo, config: Configuration
) -> bool:
    found_rejected_archived_package = (
        config.maintainability_criteria.forbid_archived
        and package_index.status == ProjectState.ARCHIVED
    )
    found_rejected_deprecated_package = (
        config.maintainability_criteria.forbid_deprecated
        and package_index.status == ProjectState.DEPRECATED
    )
    found_rejected_quarantined_package = (
        config.maintainability_criteria.forbid_quarantined
        and package_index.status == ProjectState.QUARANTINED
    )
    found_rejected_yanked_package = (
        config.maintainability_criteria.forbid_yanked and package_info.info.yanked
    )
    found_over_age_package = (
        config.maintainability_criteria.max_package_age is not None
        and package_info.age is not None
        and package_info.age > config.maintainability_criteria.max_package_age
    )
    return (
        found_rejected_archived_package
        or found_rejected_deprecated_package
        or found_rejected_quarantined_package
        or found_rejected_yanked_package
        or found_over_age_package
    )


def build_ignore_packages(config: Configuration) -> dict[str, tuple[SpecifierSet, ...]]:
    """Build the ignore packages mapping from configuration values.

    Returns:
        dict[str, tuple[SpecifierSet, ...]]: Canonical package to specifiers map.
    """
    if config.ignore_packages is None:
        return {}
    return {
        name: _get_specifier_sets(tuple(specifiers))
        for name, specifiers in config.ignore_packages.items()
    }


def process_package_metadata(
    package_info: PackageInfo | BaseException,
    package_index: PackageIndex | BaseException,
    dependency_name: str,
    config: Configuration,
    ignore_packages: dict[str, tuple[SpecifierSet, ...]],
    used_ignore_vulnerabilities: set[str],
    used_ignore_packages: set[str],
) -> DependencyOutput | str | None:
    """Process package metadata into output rows.

    Returns:
        DependencyOutput | str | None: Output row, error string, or skip marker.
    """
    if isinstance(package_info, BaseException) or isinstance(
        package_index, BaseException
    ):
        ex = package_info if isinstance(package_info, BaseException) else package_index
        return f"{dependency_name} raised exception: {ex}"

    if _should_skip_package(package_info, ignore_packages, used_ignore_packages):
        return None

    if _should_check_vulnerabilities(package_info, config):
        used_ignore_vulnerabilities.update(filter_vulnerabilities(package_info, config))
        vulns = [
            _convert_vulnerability_to_output(v) for v in package_info.vulnerabilities
        ]
    else:
        vulns = []

    pkg_index = (
        package_index
        if _should_check_maintenance_issues(package_info, config)
        else None
    )
    maintenance_issues = (
        [_convert_maintenance_to_output(package_info, package_index)]
        if pkg_index is not None
        and _has_maintenance_issues(package_index, package_info, config)
        else None
    )

    return DependencyOutput(
        name=package_info.info.name,
        version=package_info.info.version,
        direct=package_info.direct_dependency,
        vulns=vulns,
        maintenance_issues=maintenance_issues[0] if maintenance_issues else None,
    )
