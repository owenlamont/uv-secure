from datetime import timedelta
from typing import Optional

from pydantic import BaseModel, ConfigDict


class MaintainabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_package_age: Optional[timedelta] = None
    forbid_yanked: bool = False
    check_direct_dependencies_only: bool = False


class VulnerabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aliases: bool = False
    desc: bool = False
    ignore_vulnerabilities: Optional[set[str]] = None
    check_direct_dependencies_only: bool = False


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maintainability_criteria: MaintainabilityCriteria = MaintainabilityCriteria()
    vulnerability_criteria: VulnerabilityCriteria = VulnerabilityCriteria()


class OverrideConfiguration(BaseModel):
    aliases: Optional[bool] = None
    check_direct_dependency_maintenance_issues_only: Optional[bool] = None
    check_direct_dependency_vulnerabilities_only: Optional[bool] = None
    desc: Optional[bool] = None
    ignore_vulnerabilities: Optional[set[str]] = None
    forbid_yanked: Optional[bool] = None
    max_package_age: Optional[timedelta] = None


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
    if overrides.forbid_yanked is not None:
        new_configuration.maintainability_criteria.forbid_yanked = (
            overrides.forbid_yanked
        )
    if overrides.max_package_age is not None:
        new_configuration.maintainability_criteria.max_package_age = (
            overrides.max_package_age
        )

    return new_configuration
