from importlib.metadata import version


__all__ = ["__version__", "app"]
__version__ = version("uv-secure")

# Import app after defining __version__ to avoid circular imports
from uv_secure.run import app
