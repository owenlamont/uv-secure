# Coding Agent Instructions

Guidance on how to navigate and modify this codebase.

## What This Tool Does

uv-secure is an async CLI tool that scans PyPI dependencies in `uv.lock`,
`pylock.toml`, and `requirements.txt` files for known vulnerabilities and
maintenance issues. It fetches vulnerability data from PyPI's JSON API
concurrently and supports hierarchical configuration discovery.

## Code Change Requirements

- Use the uv CLI for all dependency and project changes. Do not edit
  `pyproject.toml` or `uv.lock` directly.
- Whenever code is changed, ensure all pre-commit linters pass
  (`prek run --all-files`) and all pytests pass
  (`uv run pytest -n logical --color=no`). Newly added code must keep full branch
  coverage.
- When running ad-hoc Python (inspecting objects, small scripts, etc.), use
  `uv run python` so the project venv and pinned dependencies are active.
- Update documentation whenever behaviour or feature changes are introduced.
- Diagnose bugs before patching: avoid speculative “symptom” fixes. When behaviour is
  unclear, instrument or reproduce minimally to identify the exact cause before
  landing code changes; prefer root-cause fixes over defensive clean-ups.

## Project Structure

- **/src/** – All application code lives here.
- **/tests/** – Unit and integration tests; uses pytest (tests sub-directory structure
  stays in sync with the src directory). Test modules (in most cases) are named
  according to the src module they are testing (just with a `test_` prefix) except for
  rarer tests checking functionality spanning several src modules.
- **.complexipy.toml** - Complexipy configuration
- **.coveragerc** - Coverage path mappings
- **ty.toml** - ty type checker configuration
- **pyproject.toml** - Package configuration
- **.pre-commit-config.yaml** - Pre-commit linters and some configuration
- **pytest.ini** - Pytest configuration
- **ruff.toml** - Code style and linter configuration
- **.rumdl.toml** - Markdown linter configuration
- **uv-secure.toml** - uv dependency vulnerability scanner configuration
- **.yamllint** - Yaml linter configuration

## Code Style

- Run `prek run --all-files` after every meaningful edit so its auto-fixes keep the
  working tree clean instead of treating it only as a pre-commit gate. This applies
  even to documentation-only edits because Markdown linting and wrapping rules run
  through prek.
- Remember prek won't scan any new files until they are added to git so don't
  forget to stage new files you create before running prek.
- prek will auto correct many lint and format issues, if it reports any file
  changes run a second time to see if it passes (some errors it reports on a first run
  may have been auto-corrected). Only manually resolve lint and format issues if
  prek doesn't report correcting or changing any files.
- Follow the
  [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
  for all code contributions, including Google-style docstrings.
- Use **type hinting** consistently throughout the codebase with the strongest most
  specific type hints possible. Type casting is forbidden and Any types should be kept
  to a minimum. Type ignores should almost never be used, other than for third party
  packages with no typing or dynamic typing.
- Don't create sub-packages (no `__init__.py` files) in the test directories, a
  consequence of this test strategy is no duplicate module (.py file) names are allowed
  anywhere in this repo (with the exception of `__init__.py` and `conftest.py` files)
  since pytest can't support duplicate test file names without sub-packages.
- Use the most modern Python idioms and syntax allowed by the minimum supported Python
  version (currently this is Python 3.10).
- Comments should be kept to an absolute minimum, try to achieve code readability
  through meaningful class, function, and variable names. Public functions should have
  Google-style docstrings; parameters only need to be documented if the name and type
  hint don't convey the full semantics. Private functions used within a module don't
  need docstrings (unless their names and type hints aren't sufficient to convey their
  semantics).
- Comments should only be used to explain unavoidable code smells (arising from third
  party package use), or the reason for temporary dependency version pinning (e.g.
  linking an unresolved GitHub issues) or lastly explaining opaque code or non-obvious
  trade offs or workarounds.
- Please keep all imports at the top of the module unless necessary to avoid circular
  imports

## Development Environment / Terminal

- The repo runs on macOS, Linux, and Windows. Confirm the shell environment before
  assuming POSIX semantics.
- When automation already controls the working directory, run commands directly (for
  example `prek run --all-files`) instead of prefixing them with `cd`.
- Being a uv project you never need to activate a virtual environment or call pip
  directly. Use `uv add` for dependencies and `uv run` for scripts or tooling.
- Never `git commit`, `git push`, or open/create pull requests unless the user
  explicitly asks or gives consent for those actions.
- Install `complexipy`, `markitdown`, `prek`, `rg`, `ruff`, `rumdl`, `typos`, and
  `zizmor` as global uv tools so they can be invoked without `uv run`.

## Automated Tests

- Always run `uv run pytest -n logical --color=no` when fixing bugs or making
  incremental code changes.
- For new features or larger changes run
  `uv run pytest -n logical --color=no --cov=. --cov-branch --cov-report term-missing`
  and
  inspect any uncovered lines. Some conditional logic is platform- or
  version-specific, so 100% branch coverage may require CI, but treat any gaps as
  suspect until proven otherwise.
- Tests treat warnings as errors. Fix warnings raised by this repo. Third-party
  warnings can be explicitly ignored when necessary.
- Only use test functions (no classes). Put setup into fixtures or parameters so the
  code under test is near the top of each function.
- Use explicit `pytest.param` entries with meaningful `id` strings for parametrized
  tests.
- Skip test docstrings and comments; describe intent through descriptive names and
  param ids.
- Each new test should meaningfully increase coverage. Aim for full branch coverage
  while keeping the ratio of test code to src code lean.
