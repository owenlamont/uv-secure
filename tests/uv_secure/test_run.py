from pathlib import Path

from pytest_mock import MockFixture
from typer.testing import CliRunner

from uv_secure import app


runner = CliRunner()


def test_app(mocker: MockFixture) -> None:
    mock_check_dependencies = mocker.patch("uv_secure.run.check_dependencies")
    result = runner.invoke(app, "uv.lock")
    mock_check_dependencies.assert_called_once_with(Path("uv.lock"), [])
    assert result.exit_code == 0
