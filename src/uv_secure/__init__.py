from importlib.metadata import version

from uv_secure.run import app


__all__ = ["app"]
__version__ = version(__name__)
