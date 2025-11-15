import humanize
import inflect
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from uv_secure.configuration import Configuration
from uv_secure.output_formatters.formatter import OutputFormatter
from uv_secure.output_models import (
    DependencyOutput,
    FileResultOutput,
    MaintenanceIssueOutput,
    ScanResultsOutput,
    VulnerabilityOutput,
)


class ColumnsFormatter(OutputFormatter):
    """Rich table (columns) output formatter"""

    def __init__(self, config: Configuration) -> None:
        """Initialize formatter with configuration.

        Args:
            config: Configuration controlling output columns.
        """
        self.config = config

    def format(self, results: ScanResultsOutput) -> RenderableType:
        """Format scan results as Rich renderables.

        Args:
            results: Parsed scan results.

        Returns:
            RenderableType: Group ready for Rich to display.
        """

        renderables: list[RenderableType] = []

        for file_result in results.files:
            file_renderables = self._format_file_result(file_result)
            if renderables and file_renderables:
                renderables.append(Text())
            renderables.extend(file_renderables)

        return Group(*renderables)

    def _format_file_result(
        self, file_result: FileResultOutput
    ) -> list[RenderableType]:
        """Format results for a single file.

        Args:
            file_result: File-level scan output.

        Returns:
            list[RenderableType]: Segments describing file findings.
        """

        if file_result.error:
            return [Text.from_markup(f"[bold red]Error:[/] {file_result.error}\n")]

        if not file_result.dependencies:
            if file_result.ignored_count > 0:
                inflector = inflect.engine()
                ignored_plural = inflector.plural(
                    "non-pypi dependency", file_result.ignored_count
                )
                return [
                    Panel.fit(
                        Text.from_markup(
                            f"[bold yellow]No PyPI dependencies to check[/]\n"
                            f"Ignored: [bold]{file_result.ignored_count}[/] "
                            f"{ignored_plural}"
                        )
                    )
                ]
            return [
                Panel.fit(
                    Text.from_markup(
                        "[bold green]No vulnerabilities or maintenance issues "
                        "detected![/]\nChecked: [bold]0[/] dependencies\n"
                        "All dependencies appear safe!"
                    )
                )
            ]

        renderables: list[RenderableType] = []
        renderables.append(
            Text.from_markup(
                f"[bold cyan]Checking {file_result.file_path} dependencies for "
                "vulnerabilities ...[/]\n"
            )
        )

        has_none_direct_dependency = any(
            dep.direct is None for dep in file_result.dependencies
        )
        if has_none_direct_dependency and (
            self.config.vulnerability_criteria.check_direct_dependencies_only
            or self.config.maintainability_criteria.check_direct_dependencies_only
        ):
            renderables.append(
                Text.from_markup(
                    f"[bold yellow]Warning:[/] {file_result.file_path} doesn't "
                    "contain the necessary information to determine direct "
                    "dependencies.\n"
                )
            )

        vulnerable_deps = [dep for dep in file_result.dependencies if dep.vulns]
        maintenance_items = [
            (dep, dep.maintenance_issues)
            for dep in file_result.dependencies
            if dep.maintenance_issues is not None
        ]

        total_deps = len(file_result.dependencies)
        vuln_count = sum(len(dep.vulns) for dep in vulnerable_deps)

        renderables.extend(
            self._generate_summary(
                total_deps,
                vuln_count,
                vulnerable_deps,
                maintenance_items,
                file_result.ignored_count,
            )
        )

        return renderables

    def _generate_summary(
        self,
        total_deps: int,
        vuln_count: int,
        vulnerable_deps: list[DependencyOutput],
        maintenance_items: list[tuple[DependencyOutput, MaintenanceIssueOutput]],
        ignored_count: int,
    ) -> list[RenderableType]:
        """Generate summary output with tables.

        Returns:
            list[RenderableType]: Renderables summarizing issues and counts.
        """

        renderables: list[RenderableType] = []
        inflector = inflect.engine()
        total_plural = inflector.plural("dependency", total_deps)
        vulnerable_plural = inflector.plural("vulnerability", vuln_count)
        ignored_plural = inflector.plural("non-pypi dependency", ignored_count)

        if vuln_count > 0:
            base_message = (
                f"[bold red]Vulnerabilities detected![/]\n"
                f"Checked: [bold]{total_deps}[/] {total_plural}\n"
                f"Vulnerable: [bold]{vuln_count}[/] {vulnerable_plural}"
            )
            if ignored_count > 0:
                base_message += f"\nIgnored: [bold]{ignored_count}[/] {ignored_plural}"

            renderables.extend(
                (
                    Panel.fit(Text.from_markup(base_message)),
                    self._render_vulnerability_table(vulnerable_deps),
                )
            )

        issue_count = len(maintenance_items)
        issue_plural = inflector.plural("issue", issue_count)
        if issue_count > 0:
            if renderables:
                renderables.append(Text())

            base_message = (
                f"[bold yellow]Maintenance Issues detected![/]\n"
                f"Checked: [bold]{total_deps}[/] {total_plural}\n"
                f"Issues: [bold]{issue_count}[/] {issue_plural}"
            )
            if ignored_count > 0:
                base_message += f"\nIgnored: [bold]{ignored_count}[/] {ignored_plural}"

            renderables.extend(
                (
                    Panel.fit(Text.from_markup(base_message)),
                    self._render_maintenance_table(maintenance_items),
                )
            )

        if vuln_count == 0 and issue_count == 0:
            base_message = (
                f"[bold green]No vulnerabilities or maintenance issues detected![/]\n"
                f"Checked: [bold]{total_deps}[/] {total_plural}\n"
                f"All dependencies appear safe!"
            )
            if ignored_count > 0:
                base_message += f"\nIgnored: [bold]{ignored_count}[/] {ignored_plural}"

            renderables.append(Panel.fit(Text.from_markup(base_message)))

        return renderables

    def _render_vulnerability_table(
        self, vulnerable_deps: list[DependencyOutput]
    ) -> Table:
        """Render vulnerability table.

        Args:
            vulnerable_deps: Dependencies containing vulnerabilities.

        Returns:
            Table: Rich table describing vulnerable dependencies.
        """
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
        """Create renderables for a vulnerability row.

        Args:
            dep: Dependency information.
            vuln: Vulnerability data.

        Returns:
            list[Text]: Text objects for table insertion.
        """
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
        """Create text with fix version hyperlinks.

        Args:
            package_name: Package name.
            vuln: Vulnerability data.

        Returns:
            Text: Hyperlinked fix versions.
        """
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
        """Create text with alias hyperlinks.

        Args:
            vuln: Vulnerability data.
            package_name: Package name used for PYSEC URLs.

        Returns:
            Text: Comma-separated alias text with hyperlinks when available.
        """
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
        """Get hyperlink URL for vulnerability alias.

        Args:
            alias: Alias identifier.
            package_name: Package name for PYSEC URLs.

        Returns:
            str | None: Hyperlink for known alias types, else ``None``.
        """
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
        self, maintenance_items: list[tuple[DependencyOutput, MaintenanceIssueOutput]]
    ) -> Table:
        """Render maintenance issues table.

        Args:
            maintenance_items: Dependencies paired with maintenance issues.

        Returns:
            Table: Rich table describing maintenance issues per dependency.
        """
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

        for dep, issue in maintenance_items:
            renderables = [
                Text.assemble((dep.name, f"link https://pypi.org/project/{dep.name}")),
                Text.assemble(
                    (
                        dep.version,
                        f"link https://pypi.org/project/{dep.name}/{dep.version}/",
                    )
                ),
                Text(str(issue.yanked)),
                Text(issue.yanked_reason or "Unknown"),
                (
                    Text(
                        humanize.precisedelta(
                            issue.age_days * 86400, minimum_unit="days"
                        )
                    )
                    if issue.age_days is not None
                    else Text("Unknown")
                ),
                Text(issue.status or "Unknown"),
                Text(issue.status_reason or "Unknown"),
            ]
            table.add_row(*renderables)

        return table
