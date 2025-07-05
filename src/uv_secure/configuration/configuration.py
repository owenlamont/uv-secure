from datetime import timedelta

from pydantic import BaseModel, ConfigDict


class MaintainabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_package_age: timedelta | None = None
    forbid_yanked: bool = False
    check_direct_dependencies_only: bool = False


class VulnerabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aliases: bool = False
    desc: bool = False
    ignore_vulnerabilities: set[str] | None = None
    check_direct_dependencies_only: bool = False


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maintainability_criteria: MaintainabilityCriteria = MaintainabilityCriteria()
    vulnerability_criteria: VulnerabilityCriteria = VulnerabilityCriteria()
    ignore_packages: dict[str, tuple[str, ...]] | None = None


class OverrideConfiguration(BaseModel):
    aliases: bool | None = None
    check_direct_dependency_maintenance_issues_only: bool | None = None
    check_direct_dependency_vulnerabilities_only: bool | None = None
    desc: bool | None = None
    ignore_vulnerabilities: set[str] | None = None
    ignore_packages: dict[str, tuple[str, ...]] | None = None
    forbid_yanked: bool | None = None
    max_package_age: timedelta | None = None


def override_config(
    original_config: Configuration, overrides: OverrideConfiguration
) -> Configuration:
    """Override some configuration attributes from an override configuration

    Args:
        original_config: Original unmodified configuration
        overrides: Override attributes to override in original configuration

    Returns:
        Configuration with overridden attributes
    """

    new_configuration = original_config.model_copy()
    if overrides.aliases is not None:
        new_configuration.vulnerability_criteria.aliases = overrides.aliases
    if overrides.check_direct_dependency_maintenance_issues_only is not None:
        new_configuration.maintainability_criteria.check_direct_dependencies_only = (
            overrides.check_direct_dependency_maintenance_issues_only
        )
    if overrides.check_direct_dependency_vulnerabilities_only is not None:
        new_configuration.vulnerability_criteria.check_direct_dependencies_only = (
            overrides.check_direct_dependency_vulnerabilities_only
        )
    if overrides.desc is not None:
        new_configuration.vulnerability_criteria.desc = overrides.desc
    if overrides.ignore_vulnerabilities is not None:
        new_configuration.vulnerability_criteria.ignore_vulnerabilities = (
            overrides.ignore_vulnerabilities
        )
    if overrides.ignore_packages is not None:
        new_configuration.ignore_packages = overrides.ignore_packages
    if overrides.forbid_yanked is not None:
        new_configuration.maintainability_criteria.forbid_yanked = (
            overrides.forbid_yanked
        )
    if overrides.max_package_age is not None:
        new_configuration.maintainability_criteria.max_package_age = (
            overrides.max_package_age
        )

    return new_configuration
