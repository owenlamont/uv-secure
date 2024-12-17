# uv-secure

Scan your uv.lock file for dependencies with known vulnerabilities

## Related Work and Motivation

I created this package as I wanted a dependency vulnerability scanner but I wasn't
completely happy with the options that seemed available. I use
[uv](https://docs.astral.sh/uv/) and wanted something that works with uv.lock files but
neither of the main package options I found fitted my requirements:

- [pip-audit](https://pypi.org/project/pip-audit/) only works with requirements.txt
  files but even if you convert a uv.lock file to a requirements.txt file, pip-audit
  wants to create a whole virtual environment to check all transitive dependencies (but
  that should be completely unnecessary when the lock file already contains the full
  dependencies).
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
