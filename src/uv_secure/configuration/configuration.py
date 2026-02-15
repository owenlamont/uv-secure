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


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return numeric severity rank for threshold comparisons."""
        if self == SeverityLevel.LOW:
            return 1
        if self == SeverityLevel.MEDIUM:
            return 2
        if self == SeverityLevel.HIGH:
            return 3
        return 4


class VulnerabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aliases: bool = False
    desc: bool = False
    show_severity: bool = False
    severity: SeverityLevel = SeverityLevel.LOW
    ignore_unfixed: bool = False
    ignore_vulnerabilities: set[str] | None = None
    allow_unused_ignores: bool = False
    check_direct_dependencies_only: bool = False


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maintainability_criteria: MaintainabilityCriteria = MaintainabilityCriteria()
    vulnerability_criteria: VulnerabilityCriteria = VulnerabilityCriteria()
    ignore_packages: dict[str, tuple[str, ...]] | None = None
    format: OutputFormat = OutputFormat.COLUMNS
    check_uv_tool: bool = True
    check_uv_secure: bool = True


class OverrideConfiguration(BaseModel):
    aliases: bool | None = None
    check_direct_dependency_maintenance_issues_only: bool | None = None
    check_direct_dependency_vulnerabilities_only: bool | None = None
    desc: bool | None = None
    show_severity: bool | None = None
    severity: SeverityLevel | None = None
    ignore_unfixed: bool | None = None
    ignore_vulnerabilities: set[str] | None = None
    allow_unused_ignores: bool | None = None
    ignore_packages: dict[str, tuple[str, ...]] | None = None
    forbid_archived: bool | None = None
    forbid_deprecated: bool | None = None
    forbid_quarantined: bool | None = None
    forbid_yanked: bool | None = None
    max_package_age: timedelta | None = None
    format: OutputFormat | None = None
    check_uv_tool: bool | None = None
    check_uv_secure: bool | None = None


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
    override_mappings = (
        ("aliases", new_configuration.vulnerability_criteria, "aliases"),
        (
            "check_direct_dependency_maintenance_issues_only",
            new_configuration.maintainability_criteria,
            "check_direct_dependencies_only",
        ),
        (
            "check_direct_dependency_vulnerabilities_only",
            new_configuration.vulnerability_criteria,
            "check_direct_dependencies_only",
        ),
        ("desc", new_configuration.vulnerability_criteria, "desc"),
        ("show_severity", new_configuration.vulnerability_criteria, "show_severity"),
        ("severity", new_configuration.vulnerability_criteria, "severity"),
        ("ignore_unfixed", new_configuration.vulnerability_criteria, "ignore_unfixed"),
        (
            "ignore_vulnerabilities",
            new_configuration.vulnerability_criteria,
            "ignore_vulnerabilities",
        ),
        (
            "allow_unused_ignores",
            new_configuration.vulnerability_criteria,
            "allow_unused_ignores",
        ),
        ("ignore_packages", new_configuration, "ignore_packages"),
        (
            "forbid_archived",
            new_configuration.maintainability_criteria,
            "forbid_archived",
        ),
        (
            "forbid_deprecated",
            new_configuration.maintainability_criteria,
            "forbid_deprecated",
        ),
        (
            "forbid_quarantined",
            new_configuration.maintainability_criteria,
            "forbid_quarantined",
        ),
        ("forbid_yanked", new_configuration.maintainability_criteria, "forbid_yanked"),
        (
            "max_package_age",
            new_configuration.maintainability_criteria,
            "max_package_age",
        ),
        ("format", new_configuration, "format"),
        ("check_uv_tool", new_configuration, "check_uv_tool"),
        ("check_uv_secure", new_configuration, "check_uv_secure"),
    )
    for override_attr_name, target_obj, target_attr_name in override_mappings:
        override_value = getattr(overrides, override_attr_name)
        if override_value is not None:
            setattr(target_obj, target_attr_name, override_value)
    return new_configuration
