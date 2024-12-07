from typer.testing import CliRunner

from uv_secure import app


runner = CliRunner()


def test_app() -> None:
    result = runner.invoke(app)
    assert result.exit_code == 0
