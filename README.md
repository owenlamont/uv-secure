# uv-secure

Scan your uv.lock file for dependencies with known vulnerabilities.

## Scope and Limitations

This tool will scan PyPi dependencies listed in your uv.lock files (or uv generated
requirements.txt files) and check for known vulnerabilities listed against those
packages and versions in the PyPi json API. Since it is making network requests for each
PyPi package this can be a relatively slow tool to run, and it will only work in test
environments with access to the PyPi API. Currently only packages sourced from PyPi are
tested - there's no support for custom packages or packages stored in private PyPi
servers. See roadmap below for my plans for future enhancements.

I don't intend uv-secure to ever create virtual environments or do dependency
resolution - the plan is to leave that all to uv since it does that so well and just
target lock files and fully pinned and dependency resolved requirements.txt files). If
you want a tool that does dependency resolution on requirements.txt files for first
order and unpinned dependencies I recommend using
[pip-audit](https://pypi.org/project/pip-audit/) instead.

## Disclaimer

This tool is still in an alpha phase and although it's unlikely to lose functionality
arguments may get changed with no deprecation warning. I'm still in the process of
refining the command line arguments and configuration behaviour.

## Installation

I recommend installing uv-secure as a uv tool or with pipx as it's intended to be used
as a CLI tool, and it probably only makes sense to have one version installed globally.

Installing with uv tool as follows:

```shell
uv tool install uv-secure
```

or with pipx:

```shell
pipx install uv-secure
```

you can optionally install uv-secure as a development dependency in a virtual
environment.

## Usage

After installation, you can run uv-secure --help to see the options.

```text
>> uv-secure --help

 Usage: run.py [OPTIONS] [FILE_PATHS]...

 Parse uv.lock files, check vulnerabilities, and display summary.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────╮
│   file_paths      [FILE_PATHS]...  Paths to the uv.lock or uv generated              │
│                                    requirements.txt files or a single project root   │
│                                    level directory (defaults to working directory if │
│                                    not set)                                          │
│                                    [default: None]                                   │
╰──────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────╮
│ --aliases                           Flag whether to include vulnerability aliases in │
│                                     the vulnerabilities table                        │
│ --desc                              Flag whether to include vulnerability detailed   │
│                                     description in the vulnerabilities table         │
│ --ignore              -i      TEXT  Comma-separated list of vulnerability IDs to     │
│                                     ignore, e.g. VULN-123,VULN-456                   │
│                                     [default: None]                                  │
│ --config                      PATH  Optional path to a configuration file            │
│                                     (uv-secure.toml, .uv-secure.toml, or             │
│                                     pyproject.toml)                                  │
│                                     [default: None]                                  │
│ --version                           Show the application's version                   │
│ --install-completion                Install completion for the current shell.        │
│ --show-completion                   Show completion for the current shell, to copy   │
│                                     it or customize the installation.                │
│ --help                              Show this message and exit.                      │
╰──────────────────────────────────────────────────────────────────────────────────────╯
```

```text
>> uv-secure
Checking dependencies for vulnerabilities...
╭───────────────────────────────╮
│ No vulnerabilities detected!  │
│ Checked: 160 dependencies     │
│ All dependencies appear safe! │
╰───────────────────────────────╯
```

## Configuration

uv-secure can read configuration from a toml file specified with the config option. E.g.

### uv-secure.toml / .uv-secure.toml

```toml
ignore_vulnerabilities = ["VULN-123"]
aliases = true
desc = true
```

### pyproject.toml

```toml
[tool.uv-secure]
ignore_vulnerabilities = ["VULN-123"]
aliases = true
desc = true
```

### Configuration discovery

If the ignore and config options are left unset uv-secure will search for configuration
files above each uv.lock file and use the deepest found pyproject.toml, uv-secure.toml,
or .uv-secure.toml for the configuration when processing that specific uv.lock file.
uv-secure tries to follow
[Ruff's configuration file discovery strategy](https://docs.astral.sh/ruff/configuration/#config-file-discovery)

Similar to Ruff, pyproject.toml files that don't contain uv-secure configuration are
ignored. Currently if multiple uv-secure configuration files are defined in the same
directory upstream from a uv.lock file the configurations are used in this precedence
order:

1. .uv-secure.toml
2. uv-secure.toml
3. pyproject.toml (assuming it contains uv-secure configuration)

So .uv-secure.toml files are used first, then uv-secure.toml files, and last
pyproject.toml files with uv-secure config (only if you define all three in the same
directory though - which would be a bit weird - I may make this a warning or error in
future).

Like Ruff configuration files aren't hierarchically combined, just the nearest / highest
precedence configuration is used. If you set a specific configuration file that will
take precedence and hierarchical configuration file discovery is disabled. If you do
specify a configuration options directly, e.g. pass the  --ignore option that will
overwrite the ignore_vulnerabilities setting of all found or manually specified
configuration files.

## Pre-commit Usage

uv-secure can be run as a pre-commit hook by adding this configuration to your
.pre-commit-config.yaml file:

```yaml
  - repo: https://github.com/owenlamont/uv-secure
    rev: 0.6.0
    hooks:
      - id: uv-secure
```

You should run:

```shell
pre-commit autoupdate
```

Or manually check the latest release and update the _rev_ value accordingly.

## Roadmap

Below are some ideas (in no particular order) I have for improving uv-secure:

- Package for conda on conda-forge
- Create contributor guide and coding standards doc
- Add rate limiting on how hard the PyPi json API is hit to query package
  vulnerabilities (this hasn't been a problem yet, but I suspect may be for uv.lock
  files with many dependencies)
- Explore some local caching for recording known vulnerabilities for specific package
  versions to speed up re-runs
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
want  to switch to the asyncio eventloop if installing those (I'm hoping to continue
using winloop, but it's a relatively young project and has some rough edges - I may drop
it as a dependency on Windows if it causes to many issues).

#### Debugging Async Code

Given uv-secure is often IO bound waiting on API responses or file reads I've tried to
make it as asynchronous as I can. uv-secure also uses uvloop and winloop which should be
more performant than the vanilla asyncio event loop - but they don't play nice with
Python debuggers. The hacky way at present to use asyncio event loop when debugging is
uncommenting the run import in run.py:

```python
if sys.platform in ("win32", "cygwin", "cli"):
    from winloop import run
else:
    from uvloop import run
# from asyncio import run  # uncomment for local dev and debugging
```

I definitely want to come up with a nicer scheme in the future. Either make the import
depend on an environment variable to set local development, or perhaps make uvloop and
winloop extra dependencies with asyncio event loop being the fallback so you can choose
not to include them (I need to research best/common practise here some more and pick
something).

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

## Contributing

Please raise issues for any bugs you discover with uv-secure. If practical and not too
sensitive sharing the problem uv.lock file would help me reproduce and fix these issues.

I welcome PRs for minor fixes and documentation tweaks. If you'd like to make more
substantial contributions please reach out by email / social media / or raise an
improvement issue to discuss first to make sure our plans are aligned before creating
any large / time-expensive PRs.
