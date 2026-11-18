"""npm registry client with 24h cache and offline fallback."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from plumbline.registries.cache import RegistryCache

NPM_URL = "https://registry.npmjs.org/{pkg}"


class NPMRegistry:
    """Query npm package metadata with cache and offline safety."""

    def __init__(self, cache: Optional[RegistryCache] = None, online: bool = False) -> None:
        self.cache = cache or RegistryCache()
        self.online = online

    def get_package_info(self, package_name: str) -> Optional[dict[str, Any]]:
        """Fetch package metadata from cache or live npm registry API."""
        norm_name = package_name.lower().strip()

        # 1. Check cache first
        cached = self.cache.get("npm", norm_name)
        if cached is not None:
            return cached

        # 2. If offline, return None
        if not self.online:
            return None

        # 3. Live query with short timeout
        try:
            resp = httpx.get(
                NPM_URL.format(pkg=norm_name),
                timeout=4.0,
                headers={"User-Agent": "Plumbline/0.1.0"},
                follow_redirects=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                versions = data.get("versions", {})
                meta = {
                    "exists": True,
                    "name": data.get("name", norm_name),
                    "version": data.get("dist-tags", {}).get("latest", ""),
                    "description": data.get("description", ""),
                    "releases_count": len(versions),
                    "repository": str(data.get("repository", "")),
                }
                self.cache.set("npm", norm_name, meta)
                return meta
            elif resp.status_code == 404:
                meta = {"exists": False, "name": norm_name}
                self.cache.set("npm", norm_name, meta)
                return meta
        except Exception:
            # plumbline:ignore[SLP001] Network error in registry lookup fails soft
            pass

        return None
