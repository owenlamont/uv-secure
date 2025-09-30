import humanize
import inflect
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from uv_secure.configuration import Configuration
from uv_secure.output_formatters.formatter import OutputFormatter
from uv_secure.output_models import (
    DependencyOutput,
    FileResultOutput,
    ScanResultsOutput,
    VulnerabilityOutput,
)


class ColumnsFormatter(OutputFormatter):
    """Rich table (columns) output formatter"""

    def __init__(self, config: Configuration) -> None:
        """Initialize columns formatter

        Args:
            config: Configuration for controlling output columns
        """
        self.config = config

    def format(self, results: ScanResultsOutput) -> str:
        """Format scan results as rich tables

        Args:
            results: The scan results to format

        Returns:
            Formatted string output with rich markup
        """
        console = Console()
        output_parts: list[str] = []

        for file_result in results.files:
            if file_result.error:
                output_parts.append(
                    Text.from_markup(f"[bold red]Error:[/] {file_result.error}").markup
                )
                continue

            if not file_result.dependencies:
                if file_result.ignored_count > 0:
                    inf = inflect.engine()
                    ignored_plural = inf.plural(
                        "non-pypi dependency", file_result.ignored_count
                    )
                    panel = Panel.fit(
                        f"[bold yellow]No PyPI dependencies to check[/]\n"
                        f"Ignored: [bold]{file_result.ignored_count}[/] "
                        f"{ignored_plural}"
                    )
                    with console.capture() as capture:
                        console.print(panel)
                    output_parts.append(capture.get())
                else:
                    # Show "all safe" message even if no dependencies to check
                    panel = Panel.fit(
                        "[bold green]No vulnerabilities or maintenance issues "
                        "detected![/]\nChecked: [bold]0[/] dependencies\n"
                        "All dependencies appear safe!"
                    )
                    with console.capture() as capture:
                        console.print(panel)
                    output_parts.append(capture.get())
                continue

            file_output = self._format_file_result(file_result, console)
            if file_output:
                output_parts.append(file_output)

        return "\n".join(output_parts)

    def _format_file_result(
        self, file_result: FileResultOutput, console: Console
    ) -> str:
        """Format results for a single file"""
        output_parts: list[str] = []

        # Add "Checking..." message
        checking_msg = Text.from_markup(
            f"[bold cyan]Checking {file_result.file_path} dependencies for "
            "vulnerabilities ...[/]\n"
        )
        output_parts.append(checking_msg.markup)

        # Separate vulnerabilities and maintenance issues
        vulnerable_deps = [dep for dep in file_result.dependencies if dep.vulns]
        maintenance_deps = [
            dep
            for dep in file_result.dependencies
            if dep.maintenance_issues is not None
        ]

        total_deps = len(file_result.dependencies)
        vuln_count = sum(len(dep.vulns) for dep in vulnerable_deps)

        # Generate summary
        summary = self._generate_summary(
            total_deps,
            vuln_count,
            vulnerable_deps,
            maintenance_deps,
            file_result.ignored_count,
            console,
        )
        output_parts.append(summary)

        return "\n".join(output_parts)

    def _generate_summary(
        self,
        total_deps: int,
        vuln_count: int,
        vulnerable_deps: list[DependencyOutput],
        maintenance_deps: list[DependencyOutput],
        ignored_count: int,
        console: Console,
    ) -> str:
        """Generate summary output with tables"""
        output_parts: list[str] = []
        inf = inflect.engine()
        total_plural = inf.plural("dependency", total_deps)
        vulnerable_plural = inf.plural("vulnerability", vuln_count)
        ignored_plural = inf.plural("non-pypi dependency", ignored_count)

        if vuln_count > 0:
            base_message = (
                f"[bold red]Vulnerabilities detected![/]\n"
                f"Checked: [bold]{total_deps}[/] {total_plural}\n"
                f"Vulnerable: [bold]{vuln_count}[/] {vulnerable_plural}"
            )
            if ignored_count > 0:
                base_message += f"\nIgnored: [bold]{ignored_count}[/] {ignored_plural}"

            with console.capture() as capture:
                console.print(Panel.fit(base_message))
            output_parts.append(capture.get())

            table = self._render_vulnerability_table(vulnerable_deps)
            with console.capture() as capture:
                console.print(table)
            output_parts.append(capture.get())

        issue_count = len(maintenance_deps)
        issue_plural = inf.plural("issue", issue_count)
        if issue_count > 0:
            base_message = (
                f"[bold yellow]Maintenance Issues detected![/]\n"
                f"Checked: [bold]{total_deps}[/] {total_plural}\n"
                f"Issues: [bold]{issue_count}[/] {issue_plural}"
            )
            if ignored_count > 0:
                base_message += f"\nIgnored: [bold]{ignored_count}[/] {ignored_plural}"

            with console.capture() as capture:
                console.print(Panel.fit(base_message))
            output_parts.append(capture.get())

            table = self._render_maintenance_table(maintenance_deps)
            with console.capture() as capture:
                console.print(table)
            output_parts.append(capture.get())

        if vuln_count == 0 and issue_count == 0:
            base_message = (
                f"[bold green]No vulnerabilities or maintenance issues detected![/]\n"
                f"Checked: [bold]{total_deps}[/] {total_plural}\n"
                f"All dependencies appear safe!"
            )
            if ignored_count > 0:
                base_message += f"\nIgnored: [bold]{ignored_count}[/] {ignored_plural}"

            with console.capture() as capture:
                console.print(Panel.fit(base_message))
            output_parts.append(capture.get())

        return "\n".join(output_parts)

    def _render_vulnerability_table(
        self, vulnerable_deps: list[DependencyOutput]
    ) -> Table:
        """Render vulnerability table"""
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
        if self.config.vulnerability_criteria.aliases:
            table.add_column("Aliases", min_width=20, max_width=24)
        if self.config.vulnerability_criteria.desc:
            table.add_column("Details", min_width=8)

        for dep in vulnerable_deps:
            for vuln in dep.vulns:
                renderables = self._create_vulnerability_row(dep, vuln)
                table.add_row(*renderables)

        return table

    def _create_vulnerability_row(
        self, dep: DependencyOutput, vuln: VulnerabilityOutput
    ) -> list[Text]:
        """Create renderables for vulnerability row"""
        renderables = [
            Text.assemble((dep.name, f"link https://pypi.org/project/{dep.name}")),
            Text.assemble(
                (
                    dep.version,
                    f"link https://pypi.org/project/{dep.name}/{dep.version}/",
                )
            ),
            Text.assemble((vuln.id, f"link {vuln.link}"))
            if vuln.link
            else Text(vuln.id),
            self._create_fix_versions_text(dep.name, vuln),
        ]

        if self.config.vulnerability_criteria.aliases:
            renderables.append(self._create_aliases_text(vuln, dep.name))

        if self.config.vulnerability_criteria.desc:
            renderables.append(Text(vuln.details))

        return renderables

    def _create_fix_versions_text(
        self, package_name: str, vuln: VulnerabilityOutput
    ) -> Text:
        """Create text with fix version hyperlinks"""
        if not vuln.fix_versions:
            return Text("")

        return Text(", ").join(
            [
                Text.assemble(
                    (
                        fix_ver,
                        f"link https://pypi.org/project/{package_name}/{fix_ver}/",
                    )
                )
                for fix_ver in vuln.fix_versions
            ]
        )

    def _create_aliases_text(
        self, vuln: VulnerabilityOutput, package_name: str
    ) -> Text:
        """Create text with alias hyperlinks"""
        if not vuln.aliases:
            return Text("")

        alias_links = []
        for alias in vuln.aliases:
            hyperlink = self._get_alias_hyperlink(alias, package_name)
            if hyperlink:
                alias_links.append(Text.assemble((alias, f"link {hyperlink}")))
            else:
                alias_links.append(Text(alias))

        return Text(", ").join(alias_links) if alias_links else Text("")

    def _get_alias_hyperlink(self, alias: str, package_name: str) -> str | None:
        """Get hyperlink URL for vulnerability alias"""
        if alias.startswith("CVE-"):
            return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={alias}"
        if alias.startswith("GHSA-"):
            return f"https://github.com/advisories/{alias}"
        if alias.startswith("PYSEC-"):
            return (
                "https://github.com/pypa/advisory-database/blob/main/"
                f"vulns/{package_name}/{alias}.yaml"
            )
        if alias.startswith("OSV-"):
            return f"https://osv.dev/vulnerability/{alias}"
        return None

    def _render_maintenance_table(
        self, maintenance_deps: list[DependencyOutput]
    ) -> Table:
        """Render maintenance issues table"""
        table = Table(
            title="Maintenance Issues",
            show_header=True,
            row_styles=["none", "dim"],
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Package", min_width=8, max_width=40)
        table.add_column("Version", min_width=10, max_width=20)
        table.add_column("Yanked", style="bold cyan", min_width=10, max_width=10)
        table.add_column("Yanked Reason", min_width=20, max_width=24)
        table.add_column("Age", min_width=20, max_width=24)
        table.add_column("Status", min_width=10, max_width=16)
        table.add_column("Status Reason", min_width=20, max_width=40)

        for dep in maintenance_deps:
            if dep.maintenance_issues:
                renderables = [
                    Text.assemble(
                        (dep.name, f"link https://pypi.org/project/{dep.name}")
                    ),
                    Text.assemble(
                        (
                            dep.version,
                            f"link https://pypi.org/project/{dep.name}/{dep.version}/",
                        )
                    ),
                    Text(str(dep.maintenance_issues.yanked)),
                    Text(dep.maintenance_issues.yanked_reason or "Unknown"),
                    (
                        Text(
                            humanize.precisedelta(
                                dep.maintenance_issues.age_days * 86400,
                                minimum_unit="days",
                            )
                        )
                        if dep.maintenance_issues.age_days is not None
                        else Text("Unknown")
                    ),
                    Text(dep.maintenance_issues.status or "Unknown"),
                    Text(dep.maintenance_issues.status_reason or "Unknown"),
                ]
                table.add_row(*renderables)

        return table
