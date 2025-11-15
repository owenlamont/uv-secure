from abc import ABC, abstractmethod

from rich.console import RenderableType

from uv_secure.output_models import ScanResultsOutput


class OutputFormatter(ABC):
    """Abstract base class for output formatters"""

    @abstractmethod
    def format(self, results: ScanResultsOutput) -> RenderableType:
        """Format scan results for console rendering.

        Args:
            results: Scan results to format.

        Returns:
            RenderableType: Rich renderable ready to print.
        """
