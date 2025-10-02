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
