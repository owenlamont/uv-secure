from rich.console import RenderableType

from uv_secure.output_formatters.formatter import OutputFormatter
from uv_secure.output_models import ScanResultsOutput


class JsonFormatter(OutputFormatter):
    """JSON output formatter"""

    def format(self, results: ScanResultsOutput) -> RenderableType:
        """Format scan results as JSON.

        Args:
            results: Scan results to serialize.

        Returns:
            RenderableType: JSON string with indentation.
        """
        return results.model_dump_json(indent=2, exclude_none=True)
