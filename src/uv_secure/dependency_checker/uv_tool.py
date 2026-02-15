import asyncio
from asyncio.subprocess import PIPE

from packaging.version import InvalidVersion, Version


def extract_uv_version(raw_output: str) -> str | None:
    """Parse the uv CLI version from ``uv --version`` output.

    Returns:
        str | None: Parsed version string when identifiable.
    """

    tokens = [token.strip(" ,") for token in raw_output.split() if token.strip()]
    for token in tokens:
        if token.lower() == "uv":
            continue
        try:
            Version(token)
        except InvalidVersion:
            continue
        return token
    return None


async def detect_uv_version() -> str | None:
    """Return the installed uv CLI version or ``None`` when unavailable."""

    try:
        process = await asyncio.create_subprocess_exec(
            "uv", "--version", stdout=PIPE, stderr=PIPE
        )
    except FileNotFoundError:
        return None

    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        return None

    decoded = stdout.decode(errors="ignore").strip()
    if not decoded:
        decoded = stderr.decode(errors="ignore").strip()
    if not decoded:
        return None

    return extract_uv_version(decoded)
