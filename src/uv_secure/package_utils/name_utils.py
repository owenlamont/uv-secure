import re


def canonicalize_name(name: str) -> str:
    """Convert a package name to its canonical form for PyPI URLs.

    Args:
        name: Raw package name.

    Returns:
        str: Lowercase hyphenated package name accepted by PyPI APIs.
    """
    return re.sub(r"[_.]+", "-", name).lower()
