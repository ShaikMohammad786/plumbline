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
    assert "GAP001" in result.stdout
    assert "SLP001" in result.stdout


def test_cli_explain() -> None:
    result = runner.invoke(app, ["explain", "GAP001"])
    assert result.exit_code == 0
    assert "GAP001" in result.stdout
    assert "Bad Example:" in result.stdout
    assert "Good Example:" in result.stdout


def test_cli_scan_terminal(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("import os\ndef hello(): return 'hello'", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Plumbline Repository Audit" in result.stdout
    assert "Repo Truth Score:" in result.stdout


def test_cli_scan_json(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("import os\ndef hello(): return 'hello'", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert '"schema": "plumbline.report/1"' in result.stdout


def test_cli_scan_quiet(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("import os\ndef hello(): return 'hello'", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert result.exit_code == 0
    assert result.stdout.strip() == ""


def test_cli_baseline_commands(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("# TODO: unaddressed\n", encoding="utf-8")

    baseline_file = tmp_path / "baseline.json"
    res_create = runner.invoke(
        app, ["baseline", "create", str(tmp_path), "--out", str(baseline_file)]
    )
    assert res_create.exit_code == 0
    assert baseline_file.exists()

    res_update = runner.invoke(
        app, ["baseline", "update", str(tmp_path), "--out", str(baseline_file)]
    )
    assert res_update.exit_code == 0
