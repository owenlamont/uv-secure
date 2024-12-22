from pathlib import Path
import sys

from pydantic import BaseModel


# Conditional import for toml
if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


class Dependency(BaseModel):
    name: str
    version: str


def parse_uv_lock_file(file_path: Path) -> list[Dependency]:
    """Parses a uv.lock TOML file and extracts package PyPi dependencies"""
    with file_path.open("rb") as f:
        data = toml.load(f)

    package_data = data.get("package", [])
    return [
        Dependency(name=package["name"], version=package["version"])
        for package in package_data
        if package.get("source", {}).get("registry") == "https://pypi.org/simple"
    ]
