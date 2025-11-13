# TESTING

This document explains how to run the test suite, what was changed for
testing, and what is (and is not) covered by tests.

## 1. How to Run the Tests

### 1.1. Prerequisites

- Python 3.11+
- `uv` installed
- Dependencies installed via `uv sync`

Run:

```bash
uv sync
```

### 1.2. Run the Full Test Suite

```bash
uv run pytest
```

### 1.3. Coverage

```bash
uv run pytest --cov=src --cov-report=term-missing
```

### 1.4. Run a Single Test File

```bash
uv run pytest tests/test_package_info_downloader.py
uv run pytest tests/test_dependency_file_parser.py
uv run pytest tests/test_columns_formatter.py
uv run pytest tests/test_package_index_downloader.py
uv run pytest tests/test_dependency_checker.py
```

---

## 2. Files Modified / Created

### 2.1. Source Files

The following **source** files are in scope:

- `package_info_downloader.py`
- `dependency_file_parser.py`
- `columns_formatter.py`
- `package_index_downloader.py`
- `dependency_checker.py`

### 2.2. Test Files

The following **test** files were created/extended:

- `tests/test_package_info_downloader.py`
- `tests/test_dependency_file_parser.py`
- `tests/test_columns_formatter.py`
- `tests/test_package_index_downloader.py`
- `tests/test_dependency_checker.py`

### 2.3. Configuration

- No updates to `pyproject.toml` were needed.

---

## 3. Exception Handling Enhancement (`dependency_checker.py`)

The enhanced exception-handling requirement is implemented in
`dependency_checker.py`. Key changes include:

- New custom exceptions:
  - `DependencyFileParseException`
  - `PackageMetadataProcessingException`
  - `ConfigurationResolutionException`
- Clear separation of error types:
  - Parsing errors
  - Metadata-processing errors
  - Configuration/path issues
- Original behavior is preserved while making failures more explicit and testable.

---

## 4. Custom Exceptions

### 4.1. `DependencyFileParseException`
Raised when dependency file parsing fails due to malformed content, missing fields, or unsupported formats.

### 4.2. `PackageMetadataProcessingException`
Raised when downloaded metadata is invalid, malformed, or cannot be processed.

### 4.3. `ConfigurationResolutionException`
Raised when paths or configuration values cannot be resolved correctly.

---

## 5. Test Suite Details

### 5.1. `package_info_downloader` Tests
Covers:
- Header construction  
- JSON parsing  
- Async fetch logic  
- Error handling via mocks  

### 5.2. `dependency_file_parser` Tests
Covers:
- Parsing formats (requirements, pyproject, uv.lock)  
- Direct vs transitive dependencies  
- Invalid/malformed file scenarios  
- Parametrized input variations  

### 5.3. `columns_formatter` Tests
Covers:
- Output table formatting  
- Vulnerability + fix version layout  
- Hyperlink generation for aliases  

### 5.4. `package_index_downloader` Tests
Covers:
- URL construction  
- Async scheduling with `asyncio.gather`  
- Ordering guarantees  
- Exception propagation behavior  

### 5.5. `dependency_checker` Tests
Covers:
- End-to-end dependency checking  
- Vulnerability and maintenance issue aggregation  
- JSON & column formatting  
- Alias link generation  
- Mocked HTTP interactions  
- Temporary cache usage  

---

## 6. Coverage Summary

Coverage measured using:

```bash
uv run pytest --cov=src --cov-report=term-missing
```

### **Overall Coverage**
**99% total coverage**  
(787 statements, 4 missed)

### **Coverage by File**

| File | Stmts | Missed | Coverage | Missing Lines |
|------|-------|---------|----------|----------------|
| src/uv_secure/__init__.py | 3 | 0 | 100% | — |
| src/uv_secure/__version__.py | 2 | 0 | 100% | — |
| src/uv_secure/configuration/__init__.py | 4 | 0 | 100% | — |
| src/uv_secure/configuration/config_factory.py | 32 | 1 | 97% | 18 |
| src/uv_secure/configuration/configuration.py | 66 | 0 | 100% | — |
| src/uv_secure/configuration/exceptions.py | 2 | 0 | 100% | — |
| src/uv_secure/dependency_checker/__init__.py | 2 | 0 | 100% | — |
| src/uv_secure/dependency_checker/dependency_checker.py | 183 | 1 | 99% | 52 |
| src/uv_secure/directory_scanner/__init__.py | 2 | 0 | 100% | — |
| src/uv_secure/directory_scanner/directory_scanner.py | 54 | 0 | 100% | — |
| src/uv_secure/output_formatters/__init__.py | 4 | 0 | 100% | — |
| src/uv_secure/output_formatters/columns_formatter.py | 127 | 0 | 100% | — |
| src/uv_secure/output_formatters/formatter.py | 6 | 0 | 100% | — |
| src/uv_secure/output_formatters/json_formatter.py | 6 | 0 | 100% | — |
| src/uv_secure/output_models/__init__.py | 2 | 0 | 100% | — |
| src/uv_secure/output_models/output_models.py | 20 | 0 | 100% | — |
| src/uv_secure/package_info/__init__.py | 4 | 0 | 100% | — |
| src/uv_secure/package_info/dependency_file_parser.py | 106 | 1 | 99% | 12 |
| src/uv_secure/package_info/package_index_downloader.py | 38 | 0 | 100% | — |
| src/uv_secure/package_info/package_info_downloader.py | 73 | 0 | 100% | — |
| src/uv_secure/package_utils/__init__.py | 2 | 0 | 100% | — |
| src/uv_secure/package_utils/name_utils.py | 3 | 0 | 100% | — |
| src/uv_secure/run.py | 46 | 1 | 98% | 183 |
| **TOTAL** | **787** | **4** | **99%** | — |

### **Covered Areas**
- Parser logic for all formats  
- Async downloads (mocked)  
- Vulnerability and maintenance logic  
- Formatters (JSON + table)  
- Alias/hyperlink generation  
- Enhanced exception paths  

### **Expected Uncovered Lines**
- Python-version import fallbacks (`tomllib` → `tomli`)  
- ExceptionGroup fallback (Python < 3.11)  
- Defensive/rare error states in configuration and runner code  
- CLI-only runtime branches  

---

## 7. Known Limitations

- No real HTTP requests (networking mocked for reliability)
- Terminal color formatting is not snapshot-tested

