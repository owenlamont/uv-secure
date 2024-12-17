from pathlib import Path
import sys

from pydantic import BaseModel
import typer


app = typer.Typer()

# Conditional import for toml
if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


class Dependency(BaseModel):
    name: str
    version: str


def parse_uv_lock_file(file_path: Path) -> list[Dependency]:
    """Parses a uv.lock TOML file and extract PyPi package dependencies"""
    with file_path.open("rb") as f:
        data = toml.load(f)

    package_data = data.get("package", [])
    dependencies = []

    for package in package_data:
        sdist = package.get("sdist", {}).get("url")
        wheels = package.get("wheels", [])

        if (sdist and "https://files.pythonhosted.org/" in sdist) or (
            wheels
            and "url" in wheels[0]
            and "https://files.pythonhosted.org/" in wheels[0]["url"]
        ):
            dependencies.append(
                Dependency(name=package["name"], version=package["version"])
            )

    return dependencies


@app.command()
def main(uv_lock_path: Path) -> None:
    """Parse a uv.lock file and list its dependencies"""
    if not uv_lock_path.exists():
        typer.echo(f"Error: File {uv_lock_path} does not exist.")
        raise typer.Exit(1)

    dependencies = parse_uv_lock_file(uv_lock_path)
    for dep in dependencies:
        typer.echo(f"{dep.name}=={dep.version}")


if __name__ == "__main__":
    app()
