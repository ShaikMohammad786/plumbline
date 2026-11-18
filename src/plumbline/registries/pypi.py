"""PyPI registry client with 24h cache and offline fallback."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from plumbline.registries.cache import RegistryCache

PYPI_URL = "https://pypi.org/pypi/{pkg}/json"


class PyPIRegistry:
    """Query PyPI package metadata with cache and offline safety."""

    def __init__(self, cache: Optional[RegistryCache] = None, online: bool = False) -> None:
        self.cache = cache or RegistryCache()
        self.online = online

    def get_package_info(self, package_name: str) -> Optional[dict[str, Any]]:
        """Fetch package metadata from cache or live PyPI API."""
        norm_name = package_name.lower().replace("_", "-")

        # 1. Check cache first
        cached = self.cache.get("pypi", norm_name)
        if cached is not None:
            return cached

        # 2. If offline, return None
        if not self.online:
            return None

        # 3. Live query with short timeout
        try:
            resp = httpx.get(
                PYPI_URL.format(pkg=norm_name),
                timeout=4.0,
                headers={"User-Agent": "Plumbline/0.1.0"},
                follow_redirects=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                meta = {
                    "exists": True,
                    "name": data.get("info", {}).get("name", norm_name),
                    "version": data.get("info", {}).get("version", ""),
                    "summary": data.get("info", {}).get("summary", ""),
                    "releases_count": len(data.get("releases", {})),
                    "home_page": data.get("info", {}).get("home_page")
                    or data.get("info", {}).get("project_url", ""),
                }
                self.cache.set("pypi", norm_name, meta)
                return meta
            elif resp.status_code == 404:
                meta = {"exists": False, "name": norm_name}
                self.cache.set("pypi", norm_name, meta)
                return meta
        except Exception:
            # plumbline:ignore[SLP001] Network error in registry lookup fails soft
            pass

        return None
