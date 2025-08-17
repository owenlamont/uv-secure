import re


def canonicalize_name(name: str) -> str:
    """Converts a package name to its canonical form for PyPI URLs"""
    return re.sub(r"[_.]+", "-", name).lower()
