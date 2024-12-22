import asyncio
from pathlib import Path

import inflect
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import typer

from uv_secure.package_info import download_vulnerabilities, parse_uv_lock_file


def check_dependencies(uv_lock_path: Path, ignore_ids: list[str]) -> int:
    """Checks dependencies for vulnerabilities and summarizes the results."""
    console = Console()

    if not uv_lock_path.exists():
        console.print(f"[bold red]Error:[/] File {uv_lock_path} does not exist.")
        raise typer.Exit(1)

    dependencies = parse_uv_lock_file(uv_lock_path)
    console.print(
        f"[bold cyan]Checking {uv_lock_path} dependencies for vulnerabilities...[/]"
    )

    results = asyncio.run(download_vulnerabilities(dependencies))

    total_dependencies = len(results)
    vulnerable_count = 0
    vulnerabilities_found = []

    for dep, vulnerabilities in results:
        # Filter out ignored vulnerabilities
        filtered_vulnerabilities = [
            vuln for vuln in vulnerabilities if vuln.id not in ignore_ids
        ]
        if filtered_vulnerabilities:
            vulnerable_count += 1
            vulnerabilities_found.append((dep, filtered_vulnerabilities))

    inf = inflect.engine()
    total_plural = inf.plural("dependency", total_dependencies)
    vulnerable_plural = inf.plural("dependency", vulnerable_count)

    if vulnerable_count > 0:
        console.print(
            Panel.fit(
                f"[bold red]Vulnerabilities detected![/]\n"
                f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
                f"Vulnerable: [bold]{vulnerable_count}[/] {vulnerable_plural}"
            )
        )

        table = Table(
            title="Vulnerable Dependencies",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Package", style="dim", width=20)
        table.add_column("Version", style="dim", width=10)
        table.add_column("Vulnerability ID", style="bold cyan", width=25)
        table.add_column("Details", width=40)

        for dep, vulnerabilities in vulnerabilities_found:
            for vuln in vulnerabilities:
                vuln_id_hyperlink = (
                    Text.assemble((vuln.id, f"link {vuln.link}"))
                    if vuln.link
                    else Text(vuln.id)
                )
                table.add_row(dep.name, dep.version, vuln_id_hyperlink, vuln.details)

        console.print(table)
        return 1  # Exit with failure status

    console.print(
        Panel.fit(
            f"[bold green]No vulnerabilities detected![/]\n"
            f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
            f"All dependencies appear safe!"
        )
    )
    return 0  # Exit successfully
