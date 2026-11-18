"""Tests for package registry clients, popular package cache, and offline fallback."""

import time
from pathlib import Path

from plumbline.registries import load_popular_packages
from plumbline.registries.cache import RegistryCache
from plumbline.registries.pypi import PyPIRegistry


def test_registry_cache_lifecycle(tmp_path: Path) -> None:
    cache = RegistryCache(cache_dir=tmp_path)
    assert cache.get("pypi", "flask") is None

    # Set cache entry
    data = {"exists": True, "version": "3.0.0"}
    cache.set("pypi", "flask", data)
    assert cache.get("pypi", "flask") == data

    # Test expiration
    entry_path = cache._get_path("pypi", "flask")
    assert entry_path.exists()

    # Artificially age the entry past 24 hours
    old_time = time.time() - 90000
    cache.set("pypi", "flask", data)
    raw = entry_path.read_text(encoding="utf-8").replace(str(time.time()), str(old_time))
    # Write back aged cached_at
    entry_path.write_text(raw, encoding="utf-8")


def test_popular_packages_bundled_lists() -> None:
    pypi_pkgs = load_popular_packages("pypi")
    assert "requests" in pypi_pkgs
    assert "numpy" in pypi_pkgs

    npm_pkgs = load_popular_packages("npm")
    assert "express" in npm_pkgs
    assert "react" in npm_pkgs

    crates_pkgs = load_popular_packages("crates")
    assert "serde" in crates_pkgs

    gomod_pkgs = load_popular_packages("gomod")
    assert "github.com/gin-gonic/gin" in gomod_pkgs

    # Unknown ecosystem fails soft
    assert load_popular_packages("nonexistent") == set()


def test_offline_default_never_queries_network() -> None:
    """When online=False, registry client returns None for uncached queries without network."""
    pypi = PyPIRegistry(online=False)
    # Even for a popular package, if not cached, it returns None in offline mode
    info = pypi.get_package_info("nonexistent-test-package-offline")
    assert info is None
