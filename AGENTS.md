# AGENTS.md

Guidance on how to navigate and modify this codebase.

## What This Tool Does

uv-secure is an async CLI tool that scans PyPI dependencies in `uv.lock`,
`pylock.toml`, and `requirements.txt` files for known vulnerabilities and
maintenance issues. It fetches vulnerability data from PyPI's JSON API
concurrently and supports hierarchical configuration discovery.

## Code Change Requirements

- Whenever code is changed ensure all pre-commit linters pass and all pytests pass and
  that all newly added code has full branch coverage.
- For any behaviour or feature changes ensure all documentation is updated
  appropriately.

## Project Structure

- **/src/** – All application code lives here.
- **/tests/** – Unit and integration tests; uses pytest (tests sub-directory structure
  stays in sync with the src directory). Test modules (in most cases) are named
  according to the src module they are testing (just with a `test_` prefix) except for
  rarer tests checking functionality spanning several modules.
- **pyproject.toml** - Package configuration and most linter configuration
- **markdownlint.yaml** - Markdown linter configuration
- **.pre-commit-config.yaml** - Pre-commit linters and some configuration
- **.yamllint** - Yaml linter configuration

## Code Style

- **Python**: run `pre-commit run --all-files` before committing.
- pre-commit will auto correct many lint and format issues, if it reports any file
  changes run a second time to see if it passes (some errors it reports on a first run
  may have been auto-corrected). Only manually resolve lint and format issues if
  pre-commit doesn't report correcting or changing any files.
- Follow the
  [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
  for all code contributions.
- Use **type hinting** consistently throughout the codebase (I'm a huge fan of
  strong-typing and runtime typehinting - i.e. Pydantic style)...
- Don't create sub-packages (no `__init__.py` files) in the test directories, a
  consequence of this test strategy is no duplicate module (.py file) names are allowed
  anywhere in this repo (with the obvious exception of `__init__.py` files) since pytest
  can't support duplicate test file names without sub-packages.
- Use the most modern Python idioms and syntax allowed by the minimum supported Python
  version (currently this is Python 3.10).
- Comments should be kept to an absolute minimum, try to achieve code readability
  through meaningful class, function, and variable names. Public functions should have
  docstrings - parameters only need to be documented if the name and typehint don't
  convey the full semantics of them. Private functions used within a module don't need
  docstrings (unless their names and typehints aren't sufficient to convey they
  semantics).
- Comments should only be used to explain unavoidable code smells (arising from third
  party package use), or the reason for temporary dependency version pinning (e.g.
  linking an unresolved GitHub issues) or lastly explaining opaque code or non-obvious
  trade offs or workarounds.

## Development Environment / Terminal

- uv-secure runs on Mac, Linux, and Windows. Don't make assumptions about the shell
  you're running on without checking first (it could be a Posix shell like Bash or
  Windows Powershell).
- Being a uv project you should never need to activate a virtual environment or call pip
  or python directly. Use `uv add` to add dependencies and `uv run` to run Python
  scripts or code.
- pre-commit, ruff, and complexipy should be installed as a global uv tool, they don't
  require a `uv run` prefix.

## Testing

- Always run `uv run pytest --cov=uv_secure --cov-branch --cov-report term-missing` (
  inspect the coverage table for any missing branch coverage). Note there's platform and
  Python version specific conditional logic so full 100% branch coverage can only be
  achieved by the GitHub CI tests when testing across all supported Python and platform
  versions. Inspect any missing coverage though, and if not attributable to a Python
  or platform version difference add new tests to cover the missing branch coverage.
- Prefer system tests at the CLI interface level for exercising new functionality.
- Warnings are treated with errors in tests. Warnings emitted from code in this repo
  must be addressed. Warnings emitted from third party packages can be ignored (using
  the most specific ignores practical).
