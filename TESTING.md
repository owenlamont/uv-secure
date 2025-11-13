# TESTING

This document explains how to run the test suite, what was changed for
testing, and what is (and is not) covered by tests.

## 1. How to Run the Tests

### 1.1. Prerequisites

-   Python 3.11+
-   `uv` installed
-   Dependencies installed via `uv sync`

Run:

    uv sync

### 1.2. Run the Full Test Suite

    uv run pytest

### 1.3. Coverage

    uv run pytest --cov --cov-report=term-missing

### 1.4. Run a Single Test File

    uv run pytest tests/test_package_info_downloader.py
    uv run pytest tests/test_dependency_file_parser.py
    uv run pytest tests/test_columns_formatter.py

## 2. Files Modified / Created

### 2.1. Source Files

-   `package_info_downloader.py`
-   `dependency_file_parser.py`
-   `columns_formatter.py`

### 2.2. Test Files

-   `tests/test_package_info_downloader.py`
-   `tests/test_dependency_file_parser.py`
-   `tests/test_columns_formatter.py`

### 2.3. Configuration

`pyproject.toml` updated with pytest, pytest-mock, pytest-cov, test
paths, and addopts.

## 3. Custom Exceptions

*This section will be updated once teammate completes exception
handling.*

## 4. Test Suite Details

### 4.1. package_info_downloader Tests

Tests name normalization, request headers, async downloads, JSON
parsing, and error handling. Uses parametrization and mocking.

### 4.2. dependency_file_parser Tests

Tests requirements parsing, TOML parsing, UV lock behavior, retry logic,
ignored deps, and malformed structures. Heavy use of mocking and
parametrization.

### 4.3. columns_formatter Tests

Tests alias links, fix versions, table rendering, summary generation,
and config-controlled columns. Uses parametrization and monkeypatching.

## 5. Test Coverage Summary

*Update after running coverage.*

## 6. Known Issues / Limitations

-   `tomli` import branch cannot be covered on Python 3.11+.
-   No real HTTP requests are made; tests use mocks.
-   Formatter tests validate structure, not full terminal rendering.
