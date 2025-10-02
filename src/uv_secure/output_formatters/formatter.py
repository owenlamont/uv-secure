from abc import ABC, abstractmethod

from rich.console import RenderableType

from uv_secure.output_models import ScanResultsOutput


class OutputFormatter(ABC):
    """Abstract base class for output formatters"""

    @abstractmethod
    def format(self, results: ScanResultsOutput) -> RenderableType:
        """Format scan results for console rendering

        Args:
            results: The scan results to format

        Returns:
            Rich renderable ready to be printed
        """
