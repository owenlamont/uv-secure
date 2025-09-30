from abc import ABC, abstractmethod

from uv_secure.output_models import ScanResultsOutput


class OutputFormatter(ABC):
    """Abstract base class for output formatters"""

    @abstractmethod
    def format(self, results: ScanResultsOutput) -> str:
        """Format scan results as string output

        Args:
            results: The scan results to format

        Returns:
            Formatted string output
        """
