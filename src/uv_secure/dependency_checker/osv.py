import asyncio

from httpx import AsyncClient, HTTPStatusError, RequestError
from pydantic import BaseModel, ConfigDict, ValidationError
import stamina

from uv_secure.caching.cache_manager import CacheManager
from uv_secure.configuration import SeverityLevel
from uv_secure.dependency_checker.severity import (
    extract_vulnerability_severity,
    parse_database_specific_severity,
    safe_float,
    severity_from_cvss_score,
)
from uv_secure.package_info import PackageInfo, Vulnerability


class OsvSeverityEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    score: str


class OsvDatabaseSpecific(BaseModel):
    model_config = ConfigDict(extra="ignore")
    severity: str | None = None


class OsvVulnerabilityPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str | None = None
    severity: list[OsvSeverityEntry] | None = None
    database_specific: OsvDatabaseSpecific | None = None


def _is_retryable_osv_status(status_code: int) -> bool:
    return status_code in {408, 429, 500, 502, 503, 504}


def is_known_advisory_id(advisory_id: str) -> bool:
    """Return whether an advisory ID is likely queryable via OSV."""

    return advisory_id.startswith(("GHSA-", "CVE-", "PYSEC-", "OSV-"))


def extract_osv_database_specific_severity(
    payload: OsvVulnerabilityPayload,
) -> SeverityLevel | None:
    """Extract severity from OSV's ``database_specific.severity`` field.

    Returns:
        SeverityLevel | None: Parsed severity when present.
    """

    db_severity = (
        payload.database_specific.severity
        if payload.database_specific is not None
        else None
    )
    if isinstance(db_severity, str):
        return parse_database_specific_severity(db_severity)
    return None


def extract_osv_max_numeric_cvss_score(
    payload: OsvVulnerabilityPayload,
) -> float | None:
    """Extract the maximum numeric CVSS score from OSV severity entries.

    Returns:
        float | None: Highest parsed numeric score, when available.
    """

    if not payload.severity:
        return None

    max_score: float | None = None
    for entry in payload.severity:
        score = safe_float(entry.score)
        if score is None:
            continue
        if max_score is None or score > max_score:
            max_score = score
    return max_score


def extract_osv_severity(payload: OsvVulnerabilityPayload) -> SeverityLevel | None:
    """Extract a normalized severity from an OSV vulnerability payload.

    Returns:
        SeverityLevel | None: Parsed severity when available.
    """

    database_specific_severity = extract_osv_database_specific_severity(payload)
    if database_specific_severity is not None:
        return database_specific_severity

    max_numeric_cvss_score = extract_osv_max_numeric_cvss_score(payload)
    if max_numeric_cvss_score is None:
        return None
    return severity_from_cvss_score(max_numeric_cvss_score)


async def fetch_osv_severity_data(
    advisory_id: str, http_client: AsyncClient, cache_manager: CacheManager | None
) -> tuple[SeverityLevel | None, str | None]:
    """Fetch severity metadata for an advisory ID from OSV.

    Returns:
        tuple[SeverityLevel | None, str | None]: Severity and source link.
    """

    advisory_url = f"https://api.osv.dev/v1/vulns/{advisory_id}"

    @stamina.retry(on=(RequestError, HTTPStatusError), attempts=3)
    async def fetch_from_api() -> dict[str, str | None]:
        response = await http_client.get(advisory_url)
        if _is_retryable_osv_status(response.status_code):
            raise HTTPStatusError(
                f"Retryable OSV response status: {response.status_code}",
                request=response.request,
                response=response,
            )
        if response.status_code != 200:
            return {"severity": None, "source_link": None}
        try:
            payload = OsvVulnerabilityPayload.model_validate(response.json())
        except ValidationError:
            return {"severity": None, "source_link": None}
        severity = extract_osv_severity(payload)
        if severity is None:
            return {"severity": None, "source_link": None}
        source_id = payload.id or advisory_id
        return {
            "severity": severity.value,
            "source_link": f"https://osv.dev/vulnerability/{source_id}",
        }

    try:
        if cache_manager is None:
            osv_data = await fetch_from_api()
        else:
            cache_key = f"osv-severity/{advisory_id}"
            osv_data = await cache_manager.get_or_compute(cache_key, fetch_from_api)
    except (RequestError, HTTPStatusError):
        return None, None

    raw_severity = osv_data.get("severity")
    severity = SeverityLevel(raw_severity) if isinstance(raw_severity, str) else None
    source_link = osv_data.get("source_link")
    return severity, source_link if isinstance(source_link, str) else None


def prepare_vulnerability_for_enrichment(vulnerability: Vulnerability) -> str | None:
    """Return queryable advisory ID for a vulnerability needing enrichment."""

    if extract_vulnerability_severity(vulnerability) is not None:
        if vulnerability.severity_source_link is None and vulnerability.link:
            vulnerability.severity_source_link = vulnerability.link
        return None
    if is_known_advisory_id(vulnerability.id):
        return vulnerability.id
    return None


def collect_enrichment_advisory_ids(
    package_infos: list[PackageInfo | BaseException],
) -> tuple[list[Vulnerability], set[str]]:
    """Collect vulnerabilities needing enrichment and their advisory IDs.

    Returns:
        tuple[list[Vulnerability], set[str]]: Enrichment targets and advisory IDs.
    """

    vulnerabilities_to_enrich: list[Vulnerability] = []
    advisory_ids: set[str] = set()
    for package_info in package_infos:
        if not isinstance(package_info, PackageInfo):
            continue
        for vulnerability in package_info.vulnerabilities:
            advisory_id = prepare_vulnerability_for_enrichment(vulnerability)
            if advisory_id is None:
                continue
            vulnerabilities_to_enrich.append(vulnerability)
            advisory_ids.add(advisory_id)
    return vulnerabilities_to_enrich, advisory_ids


async def enrich_vulnerability_severity_data(
    package_infos: list[PackageInfo | BaseException],
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
) -> None:
    """Populate missing vulnerability severities using OSV advisory metadata."""

    vulnerabilities_to_enrich, advisory_ids = collect_enrichment_advisory_ids(
        package_infos
    )

    if not advisory_ids:
        return

    advisory_tasks = {
        advisory_id: asyncio.create_task(
            fetch_osv_severity_data(advisory_id, http_client, cache_manager)
        )
        for advisory_id in advisory_ids
    }
    advisory_results = {
        advisory_id: await advisory_task
        for advisory_id, advisory_task in advisory_tasks.items()
    }

    for vulnerability in vulnerabilities_to_enrich:
        severity_data = advisory_results[vulnerability.id]
        severity, source_link = severity_data
        if severity is None:
            continue
        vulnerability.severity = severity.value
        vulnerability.severity_source_link = source_link
