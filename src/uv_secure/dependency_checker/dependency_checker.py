import asyncio
from collections.abc import Iterable
from pathlib import Path

from anyio import Path as APath
import inflect
from rich.console import Console, ConsoleRenderable
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import typer

from uv_secure.package_info import download_vulnerabilities, parse_uv_lock_file


async def check_dependencies(
    uv_lock_path: APath, ignore_ids: set[str]
) -> tuple[int, Iterable[ConsoleRenderable]]:
    """Checks dependencies for vulnerabilities and summarizes the results."""
    console_outputs = []

    if not await uv_lock_path.exists():
        console_outputs.append(
            f"[bold red]Error:[/] File {uv_lock_path} does not exist."
        )
        raise typer.Exit(1)

    dependencies = await parse_uv_lock_file(uv_lock_path)
    console_outputs.append(
        f"[bold cyan]Checking {uv_lock_path} dependencies for vulnerabilities...[/]"
    )

    results = await download_vulnerabilities(dependencies)

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
        console_outputs.append(
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

        console_outputs.append(table)
        return 1, console_outputs  # Exit with failure status

    console_outputs.append(
        Panel.fit(
            f"[bold green]No vulnerabilities detected![/]\n"
            f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
            f"All dependencies appear safe!"
        )
    )
    return 0, console_outputs  # Exit successfully


async def process_lock_files(
    uv_lock_paths: Iterable[Path], ignore_ids: set[str]
) -> Iterable[tuple[int, Iterable[ConsoleRenderable]]]:
    status_output_tasks = [
        check_dependencies(APath(uv_lock_path), ignore_ids)
        for uv_lock_path in uv_lock_paths
    ]
    return await asyncio.gather(*status_output_tasks)


def check_lock_files(uv_lock_paths: Iterable[Path], ignore_ids: set[str]) -> bool:
    """
    Checks

    Args:
        uv_lock_paths: paths to uv_lock files
        ignore_ids: Vulnerabilities IDs to ignore

    Returns
    -------
        True if vulnerabilities were found, False otherwise.
    """
    status_outputs = asyncio.run(process_lock_files(uv_lock_paths, ignore_ids))
    console = Console()
    vulnerabilities_found = False
    for status, console_output in status_outputs:
        console.print(*console_output)
        if status != 0:
            vulnerabilities_found = True
    return vulnerabilities_found
