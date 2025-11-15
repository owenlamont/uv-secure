from datetime import timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict


class OutputFormat(str, Enum):
    """Output format options for scan results"""

    COLUMNS = "columns"
    JSON = "json"


class MaintainabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_package_age: timedelta | None = None
    forbid_archived: bool = False
    forbid_deprecated: bool = False
    forbid_quarantined: bool = False
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
    format: OutputFormat = OutputFormat.COLUMNS
    check_uv_tool: bool = True


class OverrideConfiguration(BaseModel):
    aliases: bool | None = None
    check_direct_dependency_maintenance_issues_only: bool | None = None
    check_direct_dependency_vulnerabilities_only: bool | None = None
    desc: bool | None = None
    ignore_vulnerabilities: set[str] | None = None
    ignore_packages: dict[str, tuple[str, ...]] | None = None
    forbid_archived: bool | None = None
    forbid_deprecated: bool | None = None
    forbid_quarantined: bool | None = None
    forbid_yanked: bool | None = None
    max_package_age: timedelta | None = None
    format: OutputFormat | None = None
    check_uv_tool: bool | None = None


def override_config(
    original_config: Configuration, overrides: OverrideConfiguration
) -> Configuration:
    """Apply overrides to an existing configuration.

    Args:
        original_config: Base configuration to copy.
        overrides: Values that override matching settings.

    Returns:
        Configuration: Updated configuration with overrides applied.
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
    if overrides.forbid_archived is not None:
        new_configuration.maintainability_criteria.forbid_archived = (
            overrides.forbid_archived
        )
    if overrides.forbid_deprecated is not None:
        new_configuration.maintainability_criteria.forbid_deprecated = (
            overrides.forbid_deprecated
        )
    if overrides.forbid_quarantined is not None:
        new_configuration.maintainability_criteria.forbid_quarantined = (
            overrides.forbid_quarantined
        )
    if overrides.forbid_yanked is not None:
        new_configuration.maintainability_criteria.forbid_yanked = (
            overrides.forbid_yanked
        )
    if overrides.max_package_age is not None:
        new_configuration.maintainability_criteria.max_package_age = (
            overrides.max_package_age
        )
    if overrides.format is not None:
        new_configuration.format = overrides.format
    if overrides.check_uv_tool is not None:
        new_configuration.check_uv_tool = overrides.check_uv_tool

    return new_configuration
