"""Unit tests for plumb gate, plumb init, and git hook installation."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from plumbline.cli import app
from plumbline.hooks import install_git_hook

runner = CliRunner()


def test_install_git_hook_success(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    hook_file = install_git_hook(tmp_path)
    assert hook_file.is_file()
    assert hook_file.name == "pre-commit"
    content = hook_file.read_text(encoding="utf-8")
    assert "plumb gate" in content


def test_install_git_hook_non_git_repo(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        install_git_hook(tmp_path)


def test_cli_init_command(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", str(tmp_path)])
    assert res.exit_code == 0
    assert (tmp_path / ".plumbline.yml").is_file()
    assert (tmp_path / ".github" / "workflows" / "plumbline.yml").is_file()
    cfg_text = (tmp_path / ".plumbline.yml").read_text(encoding="utf-8")
    assert "fail_on: high" in cfg_text


def test_cli_gate_clean_repo(tmp_path: Path) -> None:
    src = tmp_path / "valid.py"
    src.write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")

    res = runner.invoke(app, ["gate", str(tmp_path), "--staged"])
    assert res.exit_code == 0
    assert "Plumbline gate passed" in res.stdout
