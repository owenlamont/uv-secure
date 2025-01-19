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
from uv_secure.directory_scanner import get_dependency_file_to_config_map
from uv_secure.package_info import (
    download_vulnerabilities,
    parse_requirements_txt_file,
    parse_uv_lock_file,
)


async def check_dependencies(
    dependency_file_path: APath, config: Configuration
) -> tuple[int, Iterable[ConsoleRenderable]]:
    """Checks dependencies for vulnerabilities and summarizes the results

    Args:
        dependency_file_path: uv.lock file or requirements.txt file path
        config: uv-secure configuration object

    Returns:
        tuple with status code and output for console to render
    """
    console_outputs = []

    if not await dependency_file_path.exists():
        console_outputs.append(
            f"[bold red]Error:[/] File {dependency_file_path} does not exist."
        )
        return 2, console_outputs

    if dependency_file_path.name == "uv.lock":
        dependencies = await parse_uv_lock_file(dependency_file_path)
    else:  # Assume dependency_file_path.name == "requirements.txt"
        dependencies = await parse_requirements_txt_file(dependency_file_path)

    if len(dependencies) == 0:
        return 0, console_outputs

    console_outputs.append(
        f"[bold cyan]Checking {dependency_file_path} dependencies for vulnerabilities"
        "...[/]"
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
            if config.ignore_vulnerabilities is None
            or vuln.id not in config.ignore_vulnerabilities
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
        table.add_column("Fix Versions", min_width=10, max_width=20)
        if config.aliases:
            table.add_column("Aliases", min_width=20, max_width=24)
        if config.desc:
            table.add_column("Details", min_width=8)

        for dep, vulnerabilities in vulnerabilities_found:
            for vuln in vulnerabilities:
                vuln_id_hyperlink = (
                    Text.assemble((vuln.id, f"link {vuln.link}"))
                    if vuln.link
                    else Text(vuln.id)
                )
                renderables = [
                    dep.name,
                    dep.version,
                    vuln_id_hyperlink,
                    ", ".join(vuln.fixed_in) if vuln.fixed_in else "",
                ]
                if config.aliases:
                    alias_links = []
                    for alias in vuln.aliases or []:
                        hyperlink = None
                        if alias.startswith("CVE-"):
                            hyperlink = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={alias}"
                        elif alias.startswith("GHSA-"):
                            hyperlink = f"https://github.com/advisories/{alias}"
                        elif alias.startswith("PYSEC-"):
                            hyperlink = f"https://github.com/pypa/advisory-database/blob/main/vulns/{dep.name}/{alias}.yaml"
                        elif alias.startswith("OSV-"):
                            hyperlink = f"https://osv.dev/vulnerability/{alias}"
                        if hyperlink:
                            alias_links.append(
                                Text.assemble((alias, f"link {hyperlink}"))
                            )
                        else:
                            alias_links.append(Text(alias))
                    renderables.append(
                        Text(", ").join(alias_links) if alias_links else Text("")
                    )
                if config.desc:
                    renderables.append(vuln.details)
                table.add_row(*renderables)

        console_outputs.append(table)
        return 1, console_outputs

    console_outputs.append(
        Panel.fit(
            f"[bold green]No vulnerabilities detected![/]\n"
            f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
            f"All dependencies appear safe!"
        )
    )
    return 0, console_outputs


class RunStatus(Enum):
    NO_VULNERABILITIES = (0,)
    VULNERABILITIES_FOUND = 1
    RUNTIME_ERROR = 2


async def check_lock_files(
    file_paths: Optional[Sequence[Path]],
    aliases: Optional[bool],
    desc: Optional[bool],
    ignore: Optional[str],
    config_path: Optional[Path],
) -> RunStatus:
    """Checks

    Args:
        file_paths: paths to files or directory to process
        aliases: flag whether to show vulnerability aliases
        desc: flag whether to show vulnerability descriptions
        ignore_ids: Vulnerabilities IDs to ignore

    Returns
    -------
        True if vulnerabilities were found, False otherwise.
    """
    if not file_paths:
        file_paths = (Path(),)

    console = Console()
    if len(file_paths) == 1 and file_paths[0].is_dir():
        lock_to_config_map = await get_dependency_file_to_config_map(
            APath(file_paths[0])
        )
        file_paths = tuple(lock_to_config_map.keys())
    else:
        if config_path is not None:
            possible_config = await config_file_factory(APath(config_path))
            config = possible_config if possible_config is not None else Configuration()
            lock_to_config_map = {APath(file): config for file in file_paths}
        elif all(
            file_path.name in {"requirements.txt", "uv.lock"}
            for file_path in file_paths
        ):
            lock_to_config_map = await get_dependency_file_to_config_map(
                [APath(file_path) for file_path in file_paths]
            )
            file_paths = tuple(lock_to_config_map.keys())
        else:
            console.print(
                "[bold red]Error:[/] file_paths must either reference a single "
                "project root directory or a sequence of uv.lock / requirements.txt "
                "file paths"
            )
            return RunStatus.RUNTIME_ERROR

    if any((aliases, desc, ignore)):
        override_config = config_cli_arg_factory(aliases, desc, ignore)
        lock_to_config_map = {
            lock_file: config.model_copy(
                update=override_config.model_dump(exclude_none=True)
            )
            for lock_file, config in lock_to_config_map.items()
        }

    status_output_tasks = [
        check_dependencies(
            APath(dependency_file_path), lock_to_config_map[APath(dependency_file_path)]
        )
        for dependency_file_path in file_paths
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
