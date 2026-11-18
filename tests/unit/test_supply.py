"""Tests for supply chain and dependency detector rules (DEP001-DEP007)."""

from pathlib import Path

from plumbline.config import PlumblineConfig
from plumbline.detectors.context import ScanContext
from plumbline.detectors.supply.rules import (
    detect_dep002,
    detect_dep004,
    detect_dep006,
    detect_dep007,
    levenshtein_distance,
)
from plumbline.ingest.manifests import Dependency
from plumbline.ingest.walker import walk_repository


def test_levenshtein_distance() -> None:
    assert levenshtein_distance("requests", "requests") == 0
    assert levenshtein_distance("requsts", "requests") == 1
    assert levenshtein_distance("reqeusts", "requests") == 2
    assert levenshtein_distance("express", "expres") == 1
    assert levenshtein_distance("", "abc") == 3


def test_dep002_typosquatting(tmp_path: Path) -> None:
    deps = [
        Dependency(
            name="reqeusts",
            spec="2.31.0",
            ecosystem="pypi",
            manifest_path="requirements.txt",
            line=1,
        ),
        Dependency(
            name="requests",
            spec="2.31.0",
            ecosystem="pypi",
            manifest_path="requirements.txt",
            line=2,
        ),
    ]
    cfg = PlumblineConfig()
    ctx = ScanContext(tmp_path, [], deps, cfg)
    findings = detect_dep002(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "DEP002"
    assert "reqeusts" in findings[0].message
    assert "requests" in findings[0].message


def test_dep004_undeclared_dependency(tmp_path: Path) -> None:
    code = tmp_path / "service.py"
    code.write_text("import redis\nr = redis.Redis()\n", encoding="utf-8")

    deps = [
        Dependency(
            name="fastapi", spec="0.110.0", ecosystem="pypi", manifest_path="pyproject.toml", line=1
        ),
    ]
    cfg = PlumblineConfig()
    walk_res = walk_repository(tmp_path, cfg)
    ctx = ScanContext(tmp_path, walk_res.files, deps, cfg)
    findings = detect_dep004(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "DEP004"
    assert "redis" in findings[0].message


def test_dep006_unpinned_wildcard(tmp_path: Path) -> None:
    deps = [
        Dependency(name="express", spec="*", ecosystem="npm", manifest_path="package.json", line=1),
    ]
    cfg = PlumblineConfig()
    ctx = ScanContext(tmp_path, [], deps, cfg)
    findings = detect_dep006(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "DEP006"


def test_dep007_cross_ecosystem_confusion(tmp_path: Path) -> None:
    code = tmp_path / "main.py"
    code.write_text("import express\n", encoding="utf-8")

    cfg = PlumblineConfig()
    walk_res = walk_repository(tmp_path, cfg)
    ctx = ScanContext(tmp_path, walk_res.files, [], cfg)
    findings = detect_dep007(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "DEP007"
    assert "express" in findings[0].message
