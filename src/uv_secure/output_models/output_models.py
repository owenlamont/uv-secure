from datetime import timedelta

from pydantic import BaseModel


class VulnerabilityOutput(BaseModel):
    """Represents a vulnerability in JSON output"""

    id: str
    details: str
    fix_versions: list[str] | None = None
    aliases: list[str] | None = None
    link: str | None = None


class MaintenanceIssueOutput(BaseModel):
    """Represents maintenance issues in JSON output"""

    yanked: bool
    yanked_reason: str | None = None
    age_days: float | None = None
    status: str | None = None
    status_reason: str | None = None


class DependencyOutput(BaseModel):
    """Represents a dependency with its vulnerabilities and maintenance issues"""

    name: str
    version: str
    direct: bool | None = None
    vulns: list[VulnerabilityOutput] = []
    maintenance_issues: MaintenanceIssueOutput | None = None


class FileResultOutput(BaseModel):
    """Enriched result for a scanned file, extends ParseResult concept"""

    file_path: str
    dependencies: list[DependencyOutput] = []
    ignored_count: int = 0
    error: str | None = None


class ScanResultsOutput(BaseModel):
    """Top-level output structure containing results for all scanned files"""

    files: list[FileResultOutput] = []


def create_vulnerability_output(
    vuln_id: str,
    details: str,
    fix_versions: list[str] | None,
    aliases: list[str] | None,
    link: str | None,
) -> VulnerabilityOutput:
    """Create VulnerabilityOutput instance"""
    return VulnerabilityOutput(
        id=vuln_id,
        details=details,
        fix_versions=fix_versions,
        aliases=aliases,
        link=link,
    )


def create_maintenance_issue_output(
    yanked: bool,
    yanked_reason: str | None,
    age: timedelta | None,
    status: str | None,
    status_reason: str | None,
) -> MaintenanceIssueOutput | None:
    """Create MaintenanceIssueOutput instance if any issue exists"""
    if (
        not yanked
        and age is None
        and status is None
        and yanked_reason is None
        and status_reason is None
    ):
        return None

    return MaintenanceIssueOutput(
        yanked=yanked,
        yanked_reason=yanked_reason,
        age_days=age.total_seconds() / 86400.0 if age else None,
        status=status,
        status_reason=status_reason,
    )
