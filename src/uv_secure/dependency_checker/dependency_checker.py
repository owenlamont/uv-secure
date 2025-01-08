import asyncio
from collections.abc import Iterable, Sequence
from enum import Enum
from pathlib import Path
from typing import Optional

from anyio import Path as APath
import inflect
from rich.console import Console, ConsoleRenderable
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from uv_secure.configuration import (
    config_cli_arg_factory,
    config_file_factory,
    Configuration,
)
from uv_secure.directory_scanner import get_lock_to_config_map
from uv_secure.package_info import download_vulnerabilities, parse_uv_lock_file


async def check_dependencies(
    uv_lock_path: APath, config: Configuration
) -> tuple[int, Iterable[ConsoleRenderable]]:
    """Checks dependencies for vulnerabilities and summarizes the results."""
    console_outputs = []

    if not await uv_lock_path.exists():
        console_outputs.append(
            f"[bold red]Error:[/] File {uv_lock_path} does not exist."
        )
        return 2, console_outputs

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
            vuln
            for vuln in vulnerabilities
            if vuln.id not in config.ignore_vulnerabilities
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
            row_styles=["none", "dim"],
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Package", min_width=8, max_width=40)
        table.add_column("Version", min_width=10, max_width=20)
        table.add_column(
            "Vulnerability ID", style="bold cyan", min_width=20, max_width=24
        )
        table.add_column("Details", min_width=8)

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


class RunStatus(Enum):
    NO_VULNERABILITIES = (0,)
    VULNERABILITIES_FOUND = 1
    RUNTIME_ERROR = 2


async def check_lock_files(
    file_paths: Optional[Sequence[Path]],
    ignore: Optional[str],
    config_path: Optional[Path],
) -> RunStatus:
    """Checks

    Args:
        file_paths: paths to files or directory to process
        ignore_ids: Vulnerabilities IDs to ignore

    Returns
    -------
        True if vulnerabilities were found, False otherwise.
    """
    if not file_paths:
        file_paths = (Path("."),)

    console = Console()
    if len(file_paths) == 1 and file_paths[0].is_dir():
        lock_to_config_map = await get_lock_to_config_map(APath(file_paths[0]))
        file_paths = tuple(lock_to_config_map.keys())
    else:
        if config_path is not None:
            possible_config = await config_file_factory(APath(config_path))
            config = possible_config if possible_config is not None else Configuration()
            lock_to_config_map = {APath(file): config for file in file_paths}
        elif all(file_path.name == "uv.lock" for file_path in file_paths):
            lock_to_config_map = await get_lock_to_config_map(
                [APath(file_path) for file_path in file_paths]
            )
            file_paths = tuple(lock_to_config_map.keys())
        else:
            console.print(
                "[bold red]Error:[/] file_paths must either reference a single "
                "project root directory or a sequence of uv.lock file paths"
            )
            return RunStatus.RUNTIME_ERROR

    if ignore is not None:
        override_config = config_cli_arg_factory(ignore)
        lock_to_config_map = {
            lock_file: config.model_copy(
                update=override_config.model_dump(exclude_none=True)
            )
            for lock_file, config in lock_to_config_map.items()
        }

    status_output_tasks = [
        check_dependencies(APath(uv_lock_path), lock_to_config_map[APath(uv_lock_path)])
        for uv_lock_path in file_paths
    ]
    status_outputs = await asyncio.gather(*status_output_tasks)
    vulnerabilities_found = False
    runtime_error = False
    for status, console_output in status_outputs:
        console.print(*console_output)
        if status == 1:
            vulnerabilities_found = True
        elif status == 2:
            runtime_error = True
    if runtime_error:
        return RunStatus.RUNTIME_ERROR
    if vulnerabilities_found:
        return RunStatus.VULNERABILITIES_FOUND
    return RunStatus.NO_VULNERABILITIES
