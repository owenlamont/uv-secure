
# Contributing to uv-secure

Thank you for your interest in contributing to **uv-secure**! This document outlines the
guidelines for contributing to ensure a smooth collaboration experience.

## Code Style and Linting

- Follow the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
  for all code contributions.
- Use **type hinting** consistently throughout the codebase.
- Use pre-commit to run linters and type checkers on all changes.
- MyPy (run by pre-commit) runs the type checking - it is prone to some false positives
  so use comments to disable checks if all else fails (but don't resort to unnecessary
  use of the Any type).

## Testing

- **Aim to maintain 100% test coverage** Ensure all changes are covered with appropriate
  unit or integration tests.
- Prefer integration tests for checking CLI input all the way through to CLI output.
- Use [pytest](https://pytest.org/) as the testing framework.
- To run tests, execute:

  ```bash
  uv run pytest
  ```

- Ensure that tests pass on all supported Python versions specified in the
  `pyproject.toml` file.
- Use the `tests` directory for organizing test cases. The file and folder structure of
  the tests should match the src folder to the extent that there are test modules that
  map to specific src modules.

## Development Environment

- I aim to support all the currently supported stable versions (3.9 through to 3.13).
- Install dependencies and development tools using [uv](https://docs.astral.sh/uv/):

  ```bash
  uv sync --dev
  ```

## Contribution Workflow

### 1. Fork the Repository

- Fork the [repository](https://github.com/owenlamont/uv-secure) and clone your fork
     locally.

### 2. Create a Branch

- Create a descriptive branch for your changes:

     ```bash
     git checkout -b feature/short-description
     ```

### 3. Make Changes

- Ensure your code follows the style guide, passes type checks, and is fully tested.
- Write clear commit messages.

### 4. Run Tests and Linting

- Run all tests and ensure high coverage:

     ```bash
     uv run pytest
     ```

- Use pre-commit for Ruff and MyPy:

- If you don't already have pre-commit installed, you only need to run this command
     once:

     ```bash
     uv tool install pre-commit
     ```

- After checking out the repository for the first time, set up the pre-commit hooks
     by running:

     ```bash
     pre-commit install
     ```

- Pre-commit will automatically run configured linters (such as Ruff and MyPy) before
     commits.

Developers can also force pre-commit to run on all files at any time by running:

```bash
pre-commit run --all-files
```

This ensures consistency across the entire codebase and still executes quite fast.

### 5. Push Changes

- Push your branch to your fork:

     ```bash
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

##

---

Thank you for helping improve uv-secure!
