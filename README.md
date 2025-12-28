# uv-secure

Scan your uv.lock file for dependencies with known vulnerabilities.

## Scope and Limitations

This tool will scan PyPi dependencies listed in your uv.lock files (or PEP751
pylock.toml files or requirements.txt files) and check for known
vulnerabilities listed against those packages and versions in the PyPi json API. Since
it is making network requests for each PyPi package this can be a relatively slow tool
to run, and it will only work in test environments with access to the PyPi API.
Currently only packages sourced from PyPi are tested - there's no support for custom
packages or packages stored in private PyPi servers. See roadmap below for my plans for
future enhancements.

When a globally installed `uv` CLI is available, uv-secure will also query the PyPI
metadata for that executable's version and report any known vulnerabilities alongside
your dependency scan results. This safety check is enabled by default but can be
disabled with `--no-check-uv-tool` or the equivalent configuration setting if
uv-secure is used in environments that do not rely on `uv`.

I don't intend uv-secure to ever create virtual environments or do dependency
resolution - the plan is to leave that all to uv since it does that so well and just
target lock files and fully pinned and (dependency resolved) requirements.txt files. If
you want a tool that does dependency resolution on requirements.txt files for first
order and unpinned dependencies I recommend using
[pip-audit](https://pypi.org/project/pip-audit/) instead.

## Disclaimer

This tool is still in an alpha phase and although it's unlikely to lose functionality
arguments may get changed with no deprecation warning. I'm still in the process of
refining the command line arguments and configuration behaviour.

## Installation

uv-secure is available on [PyPi](https://pypi.org/project/uv-secure/) and
[conda-forge](https://anaconda.org/conda-forge/uv-secure).

I recommend installing uv-secure as a uv tool, or with pipx, or as a pixi global tool as
it's intended to be used as a CLI tool, and it probably only makes sense to have one
version installed globally.

Installing with uv tool as follows:

```shell
uv tool install uv-secure
```

or with pipx:

```shell
pipx install uv-secure
```

or from conda-forge with pixi:

```shell
pixi global install uv-secure
```

you can optionally install uv-secure as a development dependency in a virtual
environment.

## Optional Dependencies

uv-secure uses highly asynchronous code to request multiple API responses or file opens
concurrently. You can install uvloop on Linux/Mac or winloop on Windows to speed up the
asynchronous event loop (at the expense of debuggability if you want to develop
uv-secure yourself). Also note, winloop is a relatively young package and may give you
some stability issues on particular versions of Python

If you want to install these faster async dependencies with uv do it with the
faster-async extension like this:

```shell
uv tool install uv-secure[faster-async]
```

or with pipx like this:

```shell
pipx install uv-secure[faster-async]
```

With pixi, given conda doesn't support optional dependencies, you can install uv-secure
globally with uvloop or winloop like this:

Mac/Linux:

```shell
pixi global install uv-secure --with uvloop
```

Windows:

```powershell
pixi global install uv-secure --with winloop
```

uv-secure will automatically use uvloop or winloop if it finds them in the same Python
environment as itself.

## Usage

After installation, you can run uv-secure --help to see the options.

```shell
>> uv-secure --help

 Usage: run.py [OPTIONS] [FILE_PATHS]...

 Parse dependency manifests and display vulnerability summaries.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────╮
│   file_paths      [FILE_PATHS]...  Paths to the uv.lock, PEP751 pylock.toml, or      │
│                                    requirements.txt files or a single project root   │
│                                    level directory (defaults to working directory if │
│                                    not set)                                          │
╰──────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────╮
│ --aliases                                                       Flag whether to      │
│                                                                 include              │
│                                                                 vulnerability        │
│                                                                 aliases in the       │
│                                                                 vulnerabilities      │
│                                                                 table                │
│ --desc                                                          Flag whether to      │
│                                                                 include              │
│                                                                 vulnerability        │
│                                                                 detailed description │
│                                                                 in the               │
│                                                                 vulnerabilities      │
│                                                                 table                │
│ --cache-path                                 PATH               Path to the cache    │
│                                                                 directory for        │
│                                                                 vulnerability http   │
│                                                                 requests             │
│                                                                 [default:            │
│                                                                 (~/.cache/uv-secure… │
│ --cache-ttl-seconds                          FLOAT              Time to live in      │
│                                                                 seconds for the      │
│                                                                 vulnerability http   │
│                                                                 requests cache       │
│                                                                 [default: 86400.0]   │
│ --disable-cache                                                 Flag whether to      │
│                                                                 disable caching for  │
│                                                                 vulnerability http   │
│                                                                 requests             │
│ --forbid-archived                                               Flag whether         │
│                                                                 disallow archived    │
│                                                                 package versions     │
│                                                                 from being           │
│                                                                 dependencies         │
│ --forbid-deprecated                                             Flag whether         │
│                                                                 disallow deprecated  │
│                                                                 package versions     │
│                                                                 from being           │
│                                                                 dependencies         │
│ --forbid-quarantin…                                             Flag whether         │
│                                                                 disallow quarantined │
│                                                                 package versions     │
│                                                                 from being           │
│                                                                 dependencies         │
│ --forbid-yanked                                                 Flag whether         │
│                                                                 disallow yanked      │
│                                                                 package versions     │
│                                                                 from being           │
│                                                                 dependencies         │
│ --max-age-days                               INTEGER            Maximum age          │
│                                                                 threshold for        │
│                                                                 packages in days     │
│ --ignore-vulns                               TEXT               Comma-separated list │
│                                                                 of vulnerability IDs │
│                                                                 or aliases to        │
│                                                                 ignore, e.g.         │
│                                                                 VULN-123,CVE-2024-1… │
│ --ignore-pkgs                                PKG:SPEC1|SPEC2|…  Dependency with      │
│                                                                 optional version     │
│                                                                 specifiers. Syntax:  │
│                                                                 name:spec1|spec2|…   │
│                                                                 e.g.                 │
│                                                                 foo:>=1.0,<1.5|==4.… │
│ --check-direct-dep…                                             Flag whether to only │
│                                                                 test only direct     │
│                                                                 dependencies for     │
│                                                                 vulnerabilities      │
│ --check-direct-dep…                                             Flag whether to only │
│                                                                 test only direct     │
│                                                                 dependencies for     │
│                                                                 maintenance issues   │
│ --config                                     PATH               Optional path to a   │
│                                                                 configuration file   │
│                                                                 (uv-secure.toml,     │
│                                                                 .uv-secure.toml, or  │
│                                                                 pyproject.toml)      │
│ --version                                                       Show the application │
│                                                                 version              │
│ --format                                     [columns|json]     Output format:       │
│                                                                 'columns' for table  │
│                                                                 output (default) or  │
│                                                                 'json' for JSON      │
│                                                                 output               │
│ --check-uv-tool        --no-check-uv-tool                       Enable or disable    │
│                                                                 scanning the         │
│                                                                 globally installed   │
│                                                                 uv CLI for           │
│                                                                 vulnerabilities      │
│                                                                 (enabled by default) │
│ --install-completi…                                             Install completion   │
│                                                                 for the current      │
│                                                                 shell.               │
│ --show-completion                                               Show completion for  │
│                                                                 the current shell,   │
│                                                                 to copy it or        │
│                                                                 customize the        │
│                                                                 installation.        │
│ --help                                                          Show this message    │
│                                                                 and exit.            │
╰──────────────────────────────────────────────────────────────────────────────────────╯
```

```shell
>> uv-secure
Checking dependencies for vulnerabilities...
╭────────────────────────────────────────────────────╮
│ No vulnerabilities or maintenance issues detected! │
│ Checked: 160 dependencies                          │
│ All dependencies appear safe!                      │
╰────────────────────────────────────────────────────╯
```

## Configuration

uv-secure can read configuration from a toml file specified with the config option. E.g.

### uv-secure.toml / .uv-secure.toml

```toml
format = "columns"
check_uv_tool = true # Disable with false to skip checking the global uv CLI

[ignore_packages]
requests = [] # Ignore issues with all versions of the requests package
urllib = [">=1.0, <2.0"] # Ignore issues between version 1.0 and less than 2.0
jinja2 = [">=0.1, <1.0", "~=2.0"] # Ignore issues between version 0.1 and 1.0 or 2.0

[vulnerability_criteria]
ignore_vulnerabilities = ["VULN-123", "CVE-2024-12345"]
aliases = true # Defaults to false
desc = true # Defaults to false
check_direct_dependencies_only = true # Defaults to false (test transitive dependencies)

[maintainability_criteria]
# max_package_age takes numeric seconds or an ISO8601 duration string
max_package_age = "P1000D" # Defaults to None if not set (no age limit)
forbid_archived = true # Defaults to false (allow archived) if not set
forbid_deprecated = true # Defaults to false (allow deprecated) if not set
forbid_quarantined = true # Defaults to false (allow quarantined) if not set
forbid_yanked = true # Defaults to false (allow yanked) if not set
```

### pyproject.toml

```toml
[tool.uv-secure]
format = "columns"

[tool.uv-secure.ignore_packages]
requests = [] # Ignore issues with all versions of the requests package
urllib = [">=1.0, <2.0"] # Ignore issues between version 1.0 and less than 2.0
jinja2 = [">=0.1, <1.0", "~=2.0"] # Ignore issues between version 0.1 and 1.0 or 2.0

[tool.uv-secure.vulnerability_criteria]
ignore_vulnerabilities = ["VULN-123", "CVE-2024-12345"]
aliases = true # Defaults to false
desc = true # Defaults to false
check_direct_dependencies_only = true # Defaults to false (test transitive dependencies)

[tool.uv-secure.maintainability_criteria]
# max_package_age takes numeric seconds or an ISO8601 duration string
max_package_age = "P1000D" # Defaults to None (no max age) if not set
forbid_yanked = true # Defaults to false (allow yanked package dependencies) if not set
forbid_archived = true # Defaults to false (allow archived) if not set
forbid_deprecated = true # Defaults to false (allow deprecated) if not set
forbid_quarantined = true # Defaults to false (allow quarantined) if not set
check_direct_dependencies_only = true # Defaults to false (test transitive dependencies)
```

### File Caching

File caching is enabled by default to speed up subsequent runs of uv-secure. By default,
cache results are saved to:

```shell
~/.cache/uv-secure
```

or on Windows

```powershell
%USERPROFILE%\.cache\uv-secure
```

This can be configured to another location if you wish.

#### Cache Performance on Windows

I'm unsure about other operating systems, but I found on Windows unless I excluded the
cache directory from the _Virus & threat protection settings_ the file caching only made
a minimal performance improvement on subsequent runs (whereas it can speed up subsequent
runs over 50% if you add the cache directory as an exclusion).

### Configuration discovery

If the ignore and config options are left unset uv-secure will search for configuration
files above each uv.lock file and use the deepest found pyproject.toml, uv-secure.toml,
or .uv-secure.toml for the configuration when processing that specific uv.lock file.
uv-secure tries to follow
[Ruff's configuration file discovery strategy](https://docs.astral.sh/ruff/configuration/#config-file-discovery)

Similar to Ruff, pyproject.toml files that don't contain uv-secure configuration are
ignored. Currently, if multiple uv-secure configuration files are defined in the same
directory upstream from a uv.lock file the configurations are used in this precedence
order:

1. .uv-secure.toml
2. uv-secure.toml
3. pyproject.toml (assuming it contains uv-secure configuration)

So .uv-secure.toml files are used first, then uv-secure.toml files, and last
pyproject.toml files with uv-secure config (only if you define all three in the same
directory though - which would be a bit weird - I may make this a warning or error in
future).

Like Ruff, configuration files aren't hierarchically combined, the nearest / highest
precedence configuration is used. If you set a specific configuration file that will
take precedence and hierarchical configuration file discovery is disabled. If you do
specify a configuration options directly, e.g. pass the --ignore option that will
overwrite the ignore_vulnerabilities setting of all found or manually specified
configuration files.

## Pre-commit Usage

uv-secure can be run as a pre-commit hook by adding this configuration to your
.pre-commit-config.yaml file:

```yaml
  - repo: https://github.com/owenlamont/uv-secure
    rev: 0.15.4
    hooks:
      - id: uv-secure
```

You should run:

```shell
prek autoupdate
```

or

```shell
pre-commit autoupdate
```

Or manually check the latest release and update the _rev_ value accordingly.

## Roadmap

Below are some ideas (in no particular order) I have for improving uv-secure:

- Integrate with GitHub / GitLab / BitBucket for additional maintenance metrics
- Add rate limiting on how hard the PyPi json API is hit to query package
  vulnerabilities (this hasn't been a problem yet, but I suspect may be for uv.lock
  files with many dependencies)
- Add support for other lock file formats beyond uv.lock
- Support some of the other output file formats pip-audit does
- Consider adding support for scanning dependencies from the current venv
- Add a severity threshold option for reporting vulnerabilities against
- Add an autofix option for updating package versions with known vulnerabilities if
  there is a more recent fixed version
- Investigate supporting private PyPi repos
- Add translations to support languages beyond English (not sure of the merits of this
  given most vulnerability reports appear to be only in English but happy to take
  feedback on this)

## Running in Development

Running uv-secure as a developer is pretty straight-forward if you have uv installed.
Just check out the repo and from a terminal in the repo root directory run:

```shell
uv sync --dev
```

To create and sync the virtual environment.

You can run the tests with:

```shell
uv run pytest
```

Or run the package entry module directly with:

```shell
uv run src/uv_secure/run.py . --aliases
```

### Debugging

If you want to run and debug uv-secure in an IDE like PyCharm or VSCode select the
virtual environment in the local .venv directory uv would have created after calling
uv sync.

#### PyCharm Warning

With PyCharm debugging relies on pip and setuptools being installed which aren't
installed by default, so I request PyCharm _Install packaging tool_ in the
_Python Interpreter_ settings (I may just add these in future are dev dependencies to
reduce the friction if this causes others too much pain). I have also encountered some
test failures on Windows if you use winloop with setuptools and pip - so you probably do
want to remove winloop if debugging in that environment if you added it.

#### Debugging Async Code

Given uv-secure is often IO bound waiting on API responses or file reads I've tried to
make it as asynchronous as I can. uv-secure also uses uvloop and winloop if installed
which should be more performant than the vanilla asyncio event loop - but they don't
play nice with Python debuggers. If you intend to do debugging I suggest leaving them
out of the virtual environment. By default, winloop or uvloop won't be installed the
repo venv unless you explicitly add them.

## Related Work and Motivation

I created this package as I wanted a dependency vulnerability scanner, but I wasn't
completely happy with the options that were available. I use
[uv](https://docs.astral.sh/uv/) and wanted something that works with uv.lock files but
neither of the main package options I found were as frictionless as I had hoped:

- [pip-audit](https://pypi.org/project/pip-audit/) uv-secure is very much based on doing
  the same vulnerability check that pip-audit does using PyPi's json API. pip-audit
  however only works with requirements.txt so to make it work with uv projects you need
  additional steps to convert your uv.lock file to a requirements.txt then you need to
  run pip-audit with the --no-deps and/or --no-pip options to stop pip-audit trying to
  create a virtual environment from the requirements.txt file. In short, you can use
  pip-audit instead of uv-secure albeit with a bit more friction for uv projects. I hope
  to add extra features beyond what pip-audit does or optimise things better (given the
  more specialised case of only needing to support uv.lock files) in the future.
- [safety](https://pypi.org/project/safety/) also doesn't work with uv.lock file out of
  the box, it does apparently work statically without needing to build a virtual
  environment but it does require you to create an account on the
  [safety site](https://platform.safetycli.com/). They have some limited free account
  but require a paid account to use seriously. If you already have a safety account
  though there is a [uv-audit](https://pypi.org/project/uv-audit/) package that wraps
  safety to support scanning uv.lock files.
- [Python Security PyCharm Plugin](https://plugins.jetbrains.com/plugin/13609-python-security)
  Lastly I was inspired by Anthony Shaw's Python Security plugin - which does CVE
  dependency scanning within PyCharm.

I build uv-secure because I wanted a CLI tool I could run with pre-commit. Statically
analyse the uv.lock file without needing to create a virtual environment, and finally
doesn't require you to create (and pay for) an account with any service.

### Related Work Updates

Some interesting developments have happened since uv-secure was released which will
possibly be better options in future to use:

- [pysentry](https://github.com/nyudenkov/pysentry) was released after uv-secure and
  looks like it supports a lot of pip-audit functionality plus parses multiple lock file
  formats. This tool looks promising, implemented in Rust which I love and will possibly
  subsume uv-secure features... but it's still early days so I will monitor its
  adoption. May deprecate uv-secure in future in favour of pysentry if it overlaps
  enough uv-secure features.
- [pyx](https://astral.sh/blog/introducing-pyx) also revealed very recently is Astral's
  pyx package repository service which indicates it will do vulnerability and package
  status scanning for you. This looks really appealing, but uv-secure was motivated to
  avoid relying on paid services so it doesn't fit the niche exactly.

## Contributing

Please raise issues for any bugs you discover with uv-secure. If practical and not too
sensitive sharing the problem uv.lock file would help me reproduce and fix these issues.

I welcome PRs for minor fixes and documentation tweaks. If you'd like to make more
substantial contributions please reach out by email / social media / or raise an
improvement issue to discuss first to make sure our plans are aligned before creating
any large / time-expensive PRs.

See the [contributing guide](https://github.com/owenlamont/uv-secure/blob/main/CONTRIBUTING.md)
for more details on contributing to uv-secure
