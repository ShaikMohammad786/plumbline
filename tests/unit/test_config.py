"""Unit tests for Plumbline configuration."""

from pathlib import Path

import pytest

from plumbline.config import load_config


def test_default_config(tmp_path: Path) -> None:
    non_existent = tmp_path / ".plumbline.yml"
    cfg = load_config(non_existent)
    assert cfg.version == 1
    assert cfg.fail_on == "high"
    assert cfg.online is False
    assert cfg.scan.max_file_kb == 1024


def test_cli_overrides(tmp_path: Path) -> None:
    cfg_file = tmp_path / ".plumbline.yml"
    cfg_file.write_text("version: 1\nfail_on: low\nonline: false\n", encoding="utf-8")

    cfg = load_config(cfg_file, fail_on="critical", online=True)
    assert cfg.fail_on == "critical"
    assert cfg.online is True


def test_unknown_key_error(tmp_path: Path) -> None:
    cfg_file = tmp_path / ".plumbline.yml"
    cfg_file.write_text("version: 1\nscan:\n  invalid_key: 123\n", encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        load_config(cfg_file)
    assert "scan.invalid_key" in str(exc.value)


def test_env_var_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLUMBLINE_FAIL_ON", "medium")
    monkeypatch.setenv("PLUMBLINE_ONLINE", "true")

    cfg = load_config(tmp_path / ".plumbline.yml")
    assert cfg.fail_on == "medium"
    assert cfg.online is True
