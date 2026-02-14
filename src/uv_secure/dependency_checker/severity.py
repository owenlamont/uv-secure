from cvss import CVSS2, CVSS3, CVSS4, CVSSError

from uv_secure.configuration import SeverityLevel
from uv_secure.package_info import Vulnerability


def extract_vulnerability_severity(
    vulnerability: Vulnerability,
) -> SeverityLevel | None:
    """Extract normalized severity for a vulnerability, if available.

    Returns:
        SeverityLevel | None: Parsed severity or ``None`` when unavailable.
    """

    severity = vulnerability.severity
    if severity is None:
        return None
    return severity_from_str(severity)


def severity_from_str(raw_severity: str) -> SeverityLevel | None:
    """Map a raw severity string or score string to an enum value.

    Returns:
        SeverityLevel | None: Parsed severity or ``None`` when unrecognized.
    """

    normalized = raw_severity.strip().lower()
    try:
        return SeverityLevel(normalized)
    except ValueError:
        pass

    parsed_score = parse_cvss_score(normalized)
    if parsed_score is None:
        return None
    return severity_from_cvss_score(parsed_score)


def parse_cvss_score(raw_score: str) -> float | None:
    """Parse a CVSS score string as numeric score or vector-derived score.

    Returns:
        float | None: Parsed CVSS base score or ``None`` when invalid.
    """

    numeric_score = safe_float(raw_score)
    if numeric_score is not None:
        return numeric_score

    score_parsers = (CVSS4, CVSS3, CVSS2)
    for score_parser in score_parsers:
        try:
            cvss_value = score_parser(raw_score)
        except CVSSError:
            continue
        return float(cvss_value.scores()[0])

    return None


def safe_float(value: str) -> float | None:
    """Parse a float-like string and return ``None`` when invalid.

    Returns:
        float | None: Parsed float value or ``None`` when conversion fails.
    """

    try:
        return float(value)
    except ValueError:
        return None


def severity_from_cvss_score(score: float) -> SeverityLevel:
    """Convert a CVSS score to a normalized severity bucket.

    Returns:
        SeverityLevel: Severity bucket derived from CVSS thresholds.
    """

    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def parse_database_specific_severity(raw_severity: str) -> SeverityLevel | None:
    """Map OSV database-specific severity text to ``SeverityLevel``.

    Returns:
        SeverityLevel | None: Parsed severity label when recognized.
    """

    normalized = raw_severity.strip().lower()
    if normalized in {"moderate", "medium"}:
        return SeverityLevel.MEDIUM
    if normalized == "important":
        return SeverityLevel.HIGH
    try:
        return SeverityLevel(normalized)
    except ValueError:
        return None
