
# Contributing to uv-secure

Thank you for your interest in contributing to **uv-secure**! This document outlines the
guidelines for contributing to ensure a smooth collaboration experience. I'd love to get
more contributors, even for small changes like documentation fixes, examples, or
additional tests, partly just because I know a lot of people won't adopt uv-secure if
they don't see multiple contributors.

## Code Style and Linting

- Follow the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
  for all code contributions.
- Use **type hinting** consistently throughout the codebase (I'm a huge fan of
  strong-typing and runtime typehinting - i.e. Pydantic style)...
- Use pre-commit to run linters and type checkers on all changes.
- MyPy (run by pre-commit) runs the type checking - it is prone to some false positives
  so use comments to disable checks if all else fails (but don't resort to unnecessary
  use of the _Any_ type).

## Testing

- **Aim to maintain 100% test coverage** Ensure all changes are covered with appropriate
  unit or integration tests. Note there is some platform / Python version specific logic
  so you'll only see full test coverage in CI which merges coverage across those
  dimensions.
- Prefer integration tests for checking CLI input all the way through to CLI output.
- Use [pytest](https://pytest.org/) as the testing framework.
- To run tests, execute:

  ```shell
  uv run pytest
  ```

- Use the `tests` directory for organizing test cases. The file and folder structure of
  the tests directory should match the src folder to the extent that there are test
  modules that map to specific src modules.
- The test module for a src module should have the same name as the src module except
  the test module will have a `test_` prefix. I want to use this scheme to make it easy
  to find the tests for any given logic.
- We don't create sub-packages (no `__init__.py` files) in the test directories, a
  consequence of this test strategy is no duplicate module (.py file) names are allowed
  anywhere in this repo (with the obvious exception of `__init__.py` files) since pytest
  can't support duplicate test file names without sub-packages. I think that is a good
  constraint though as duplicate .py file names make looking up linter issues harder.

## Development Environment

- I aim to support all the currently supported stable versions of Python (3.9 through to
  3.13).
- Install dependencies and development tools using [uv](https://docs.astral.sh/uv/):

  ```shell
  uv sync --dev
  ```

## Contribution Workflow

### 1. Fork the Repository

- Fork the [repository](https://github.com/owenlamont/uv-secure) and clone your fork
  locally.

### 2. Create a Branch

- Create a descriptive branch for your changes:

     ```shell
     git checkout -b feature/short-description
     ```

### 3. Make Changes

- Ensure your code follows the style guide, passes type checks, and is fully tested.
- Write clear commit messages.

### 4. Run Tests and Linting

- Run all tests and ensure high coverage:

     ```shell
     uv run pytest
     ```

- Use pre-commit for Ruff and MyPy:

- If you don't already have pre-commit installed, you only need to run this command
  once:

     ```shell
     uv tool install pre-commit
     ```

- After checking out the repository for the first time, set up the pre-commit hooks
  by running:

     ```shell
     pre-commit install
     ```

- Pre-commit will automatically run configured linters (such as Ruff and MyPy) before
  commits.

Developers can also force pre-commit to run on all files at any time by running:

```shell
pre-commit run --all-files
```

This ensures consistency across the entire codebase and still executes quite fast.

### 5. Push Changes

- Push your branch to your fork:

     ```shell
     git push origin feature/short-description
     ```

### 6. Open a Pull Request (PR)

- Open a PR from your branch to the `main` branch of the repository.
- Clearly describe the changes you’ve made and reference any related issues.

### 7. Respond to Feedback

- Address any comments or feedback provided during the review process.

## Reporting Issues

If you encounter a bug or have a feature request, please
[create an issue](https://github.com/owenlamont/uv-secure/issues) on GitHub. Include as
much detail as possible to help reproduce the issue or understand the feature request (
providing any problem uv.lock files or requirements.txt files would help).

---

Thank you for helping improve uv-secure!
