"""Go proxy registry client with 24h cache and offline fallback."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from plumbline.registries.cache import RegistryCache

GOPROXY_URL = "https://proxy.golang.org/{pkg}/@v/list"


class GoModRegistry:
    """Query Go proxy module metadata with cache and offline safety."""

    def __init__(self, cache: Optional[RegistryCache] = None, online: bool = False) -> None:
        self.cache = cache or RegistryCache()
        self.online = online

    def get_package_info(self, package_name: str) -> Optional[dict[str, Any]]:
        norm_name = package_name.lower().strip()

        cached = self.cache.get("gomod", norm_name)
        if cached is not None:
            return cached

        if not self.online:
            return None

        try:
            resp = httpx.get(
                GOPROXY_URL.format(pkg=norm_name),
                timeout=4.0,
                headers={"User-Agent": "Plumbline/0.1.0"},
                follow_redirects=True,
            )
            if resp.status_code == 200:
                versions = resp.text.strip().splitlines()
                meta = {
                    "exists": True,
                    "name": norm_name,
                    "version": versions[-1] if versions else "",
                    "releases_count": len(versions),
                }
                self.cache.set("gomod", norm_name, meta)
                return meta
            elif resp.status_code in (404, 410):
                meta = {"exists": False, "name": norm_name}
                self.cache.set("gomod", norm_name, meta)
                return meta
        except Exception:
            # plumbline:ignore[SLP001] Network error in registry lookup fails soft
            pass

        return None
