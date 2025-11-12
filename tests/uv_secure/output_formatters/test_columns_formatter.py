from types import SimpleNamespace

import pytest
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import uv_secure.output_formatters.columns_formatter as cf


class _Cfg:
    """Minimal config double with only the flags used by ColumnsFormatter."""

    def __init__(self, aliases: bool = True, desc: bool = True):
        self.vulnerability_criteria = SimpleNamespace(aliases=aliases, desc=desc)


def _dep(name="pkg", version="1.0.0", vulns=None):
    return SimpleNamespace(name=name, version=version, vulns=vulns or [])


def _vuln(
    vuln_id="CVE-0000-0000",
    severity="HIGH",
    cvss_score=9.8,
    fix_versions=None,
    aliases=None,
    desc=None,
    details=None,
    link=None,
    yanked=None,
    yanked_reason=None,
    age_days=None,
    status=None,
    status_reason=None,
):
    return SimpleNamespace(
        id=vuln_id,
        severity=severity,
        cvss_score=cvss_score,
        fix_versions=fix_versions or [],
        aliases=aliases or [],
        desc=desc,
        details=(details or desc or ""),
        link=link,
        yanked=yanked,
        yanked_reason=yanked_reason,
        age_days=age_days,
        status=status,
        status_reason=status_reason,
    )


@pytest.mark.parametrize(
    ("alias", "pkg", "expected_start"),
    [
        (
            "CVE-2024-12345",
            "requests",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
        ),
        ("GHSA-abc1-xyz2-zzz3", "requests", "https://github.com/advisories/"),
        (
            "PYSEC-2024-42",
            "urllib3",
            "https://github.com/pypa/advisory-database/blob/main/vulns/urllib3/",
        ),
        ("OSV-2024-0001", "flask", "https://osv.dev/vulnerability/"),
    ],
    ids=["CVE", "GHSA", "PYSEC", "OSV"],
)
def test_get_alias_hyperlink_recognized(alias, pkg, expected_start):
    fmt = cf.ColumnsFormatter(_Cfg())
    url = fmt._get_alias_hyperlink(alias, pkg)
    assert url.startswith(expected_start)
    assert alias in url


def test_get_alias_hyperlink_unrecognized():
    fmt = cf.ColumnsFormatter(_Cfg())
    assert fmt._get_alias_hyperlink("FOO-1", "pkg") is None


def test_create_fix_versions_text_empty():
    fmt = cf.ColumnsFormatter(_Cfg())
    t = fmt._create_fix_versions_text("pkg", _vuln(fix_versions=[]))
    assert isinstance(t, Text)
    assert t.plain == ""


def test_create_fix_versions_text_links_and_joining():
    fmt = cf.ColumnsFormatter(_Cfg())
    v = _vuln(fix_versions=["1.2.3", "2.0.0"])
    t = fmt._create_fix_versions_text("demo", v)
    assert t.plain == "1.2.3, 2.0.0"


def test_create_aliases_text_mixed_links_and_plain():
    fmt = cf.ColumnsFormatter(_Cfg())
    v = _vuln(aliases=["CVE-2023-1111", "FOO-1"])
    t = fmt._create_aliases_text(v, "demo")
    assert t.plain == "CVE-2023-1111, FOO-1"


def test_create_aliases_text_empty():
    fmt = cf.ColumnsFormatter(_Cfg())
    v = _vuln(aliases=[])
    t = fmt._create_aliases_text(v, "demo")
    assert t.plain == ""


@pytest.mark.parametrize(
    ("aliases_flag", "desc_flag"),
    [
        (False, False),
        (True, False),
        (False, True),
        (True, True),
    ],
    ids=["base", "aliases", "details", "aliases+details"],
)
def test_render_vulnerability_table_adds_optional_columns(aliases_flag, desc_flag):
    fmt = cf.ColumnsFormatter(_Cfg(aliases=aliases_flag, desc=desc_flag))
    deps = [
        _dep("a", "1.0.0", [_vuln(vuln_id="CVE-1", link="https://example/a")]),
        _dep(
            "b",
            "2.0.0",
            [_vuln(vuln_id="GHSA-2", link="https://example/b"), _vuln(vuln_id="OSV-3")],
        ),
    ]
    table = fmt._render_vulnerability_table(deps)
    assert isinstance(table, Table)
    headers = [
        h if isinstance((h := c.header), str) else getattr(h, "plain", str(h))
        for c in table.columns
    ]

    assert headers[:2] == ["Package", "Version"]
    assert "Vulnerability ID" in headers
    assert "Fix Versions" in headers

    if aliases_flag:
        assert "Aliases" in headers
    else:
        assert "Aliases" not in headers

    if desc_flag:
        assert any(h in headers for h in ("Details", "Description"))
    else:
        assert all(h not in headers for h in ("Details", "Description"))

    assert table.row_count == 3


def test_render_maintenance_table_age_and_unknown(monkeypatch):
    fmt = cf.ColumnsFormatter(_Cfg())

    calls = {}

    def fake_precisedelta(seconds, minimum_unit="days"):
        calls["arg"] = seconds
        return "N days"

    monkeypatch.setattr(cf.humanize, "precisedelta", fake_precisedelta)

    dep1 = _dep("x", "0.1.0")
    issue1 = _vuln(age_days=5, status="yanked", status_reason="bad")
    dep2 = _dep("y", "0.2.0")
    issue2 = _vuln(age_days=None, status=None, status_reason=None)

    table = fmt._render_maintenance_table([(dep1, issue1), (dep2, issue2)])

    assert isinstance(table, Table)
    assert calls["arg"] == 5 * 86400
    assert table.row_count == 2


def test_create_vulnerability_row_basic_cells():
    fmt = cf.ColumnsFormatter(_Cfg(aliases=False, desc=False))
    dep = _dep("demo", "1.0.0")
    v = _vuln(
        vuln_id="CVE-9",
        severity="LOW",
        cvss_score=3.0,
        fix_versions=["1.0.1"],
        link="https://example/cve-9",
    )
    cells = fmt._create_vulnerability_row(dep, v)
    assert isinstance(cells, list)
    assert len(cells) >= 4
    plain_values = [c.plain if isinstance(c, Text) else str(c) for c in cells]
    for expected in ("demo", "1.0.0", "CVE-9", "1.0.1"):
        assert any(expected in s for s in plain_values)


@pytest.mark.parametrize(
    ("vuln_count", "maint_count", "ignored", "expect_tables"),
    [
        (2, 0, 0, 2),
        (0, 3, 1, 2),
        (0, 0, 2, 1),
        (2, 2, 0, 3),
    ],
)
def test_generate_summary_branching(
    vuln_count, maint_count, ignored, expect_tables, mocker
):
    fmt = cf.ColumnsFormatter(_Cfg())
    mocker.patch.object(fmt, "_render_vulnerability_table", return_value=Table())
    mocker.patch.object(fmt, "_render_maintenance_table", return_value=Table())

    total_deps = 10
    vulnerable_deps = [_dep("a", "1", [_vuln(link="https://ex")])] * vuln_count
    maintenance_items = [(_dep("b", "2"), _vuln())] * maint_count

    out = fmt._generate_summary(
        total_deps=total_deps,
        vuln_count=vuln_count,
        vulnerable_deps=vulnerable_deps,
        maintenance_items=maintenance_items,
        ignored_count=ignored,
    )

    panels = [r for r in out if isinstance(r, Panel)]
    tables = [r for r in out if isinstance(r, Table)]
    if vuln_count == 0 and maint_count == 0:
        assert len(panels) == 1
        assert len(tables) == 0
    else:
        assert len(tables) in (1, 2)
        assert len(panels) in (1, 2)
