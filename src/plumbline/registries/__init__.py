"""Registry clients and popular package catalogues for Plumbline."""

from __future__ import annotations

from pathlib import Path

from plumbline.registries.cache import RegistryCache
from plumbline.registries.crates import CratesRegistry
from plumbline.registries.gomod import GoModRegistry
from plumbline.registries.npm import NPMRegistry
from plumbline.registries.pypi import PyPIRegistry
from plumbline.registries.rubygems import RubyGemsRegistry

POPULAR_DIR = Path(__file__).parent / "popular"

_POPULAR_CACHE: dict[str, set[str]] = {}


def load_popular_packages(ecosystem: str) -> set[str]:
    """Load bundled popular package list for ecosystem (pypi, npm, crates, gomod, rubygems)."""
    if ecosystem in _POPULAR_CACHE:
        return _POPULAR_CACHE[ecosystem]

    target = POPULAR_DIR / f"{ecosystem}.txt"
    if not target.exists():
        _POPULAR_CACHE[ecosystem] = set()
        return set()

    try:
        lines = [
            line.strip().lower()
            for line in target.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        res = set(lines)
        _POPULAR_CACHE[ecosystem] = res
        return res
    except Exception:
        # plumbline:ignore[SLP001] Popular package loading fallback
        return set()


__all__ = [
    "RegistryCache",
    "PyPIRegistry",
    "NPMRegistry",
    "CratesRegistry",
    "GoModRegistry",
    "RubyGemsRegistry",
    "load_popular_packages",
]
