"""Unit tests for Plumbline CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from plumbline.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Plumbline" in result.stdout
    assert "0.1.0" in result.stdout


def test_cli_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "Plumbline Detection Rules" in result.stdout


def test_cli_scan(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("import os\nprint('hello')", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Plumbline Repository Ingest" in result.stdout
    assert "Total Files Ingested" in result.stdout


def test_cli_scan_quiet(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("import os\nprint('hello')", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert result.exit_code == 0
    assert result.stdout.strip() == ""
