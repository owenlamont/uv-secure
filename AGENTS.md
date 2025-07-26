# AGENTS.md

Guidance on how to navigate and modify this codebase.

## What This Tool Does

uv-secure is an async CLI tool that scans PyPI dependencies in `uv.lock`,
`pylock.toml`, and `requirements.txt` files for known vulnerabilities and
maintenance issues. It fetches vulnerability data from PyPI's JSON API
concurrently and supports hierarchical configuration discovery.

## Project Structure

- **/src/** – All application code lives here.
- **/tests/** – Unit and integration tests; uses pytest (tests sub-directory structure
  stays in sync with the src directory). Test modules (in most cases) are named
  according to the src module they are testing (just with a `test_` prefix) except for
  rarer tests checking functionality spanning several modules.
- **pyproject.toml** - Package configuration and most linter configuration
- **markdownlinst.yaml** - Markdown linter configuration
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

## Testing

- Always run `uv run pytest --cov=uv_secure --cov-branch --cov-report term-missing` (
  inspect the coverage table for any missing branch coverage). Note there's platform and
  Python version specific conditional logic so full 100% branch coverage can only be
  achieved by the GitHub CI tests when testing across all supported Python and platform
  versions. Inspect any missing coverage though, and if not attributable to a Python
  or platform version difference add new tests to cover the missing branch coverage.
- Prefer system tests at the CLI interface level for exercising new functionality.
- uv-secure runs on Mac, Linux, and Windows. Don't make assumptions about the shell
  you're running on without checking first (it could be a Posix shell like Bash or
  Windows Powershell).

## PR Guidelines

- Title: `<type>(<scope>): <short description>`
- Body:
  1. What changed
  2. How to verify
  3. Any breaking changes
