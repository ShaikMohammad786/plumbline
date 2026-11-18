"""Manifest parsing across ecosystems using standard library tools."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class Dependency:
    name: str
    spec: str
    ecosystem: str  # pypi, npm, gomod, crates, maven, rubygems, composer
    manifest_path: str
    line: int
    dev: bool = False


def parse_manifest(file_path: Path, relative_path: str) -> list[Dependency]:
    """Parse dependencies from a manifest file based on filename."""
    filename = file_path.name.lower()

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    if filename == "package.json":
        return _parse_package_json(content, relative_path)
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return _parse_requirements_txt(content, relative_path)
    if filename == "pyproject.toml":
        return _parse_pyproject_toml(content, relative_path)
    if filename == "pipfile":
        return _parse_pipfile(content, relative_path)
    if filename == "go.mod":
        return _parse_go_mod(content, relative_path)
    if filename == "cargo.toml":
        return _parse_cargo_toml(content, relative_path)
    if filename == "pom.xml":
        return _parse_pom_xml(content, relative_path)
    if filename in ("build.gradle", "build.gradle.kts"):
        return _parse_gradle(content, relative_path)
    if filename == "gemfile":
        return _parse_gemfile(content, relative_path)
    if filename == "composer.json":
        return _parse_composer_json(content, relative_path)

    return []


def _parse_package_json(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(content)
    except Exception:
        return []

    lines = content.splitlines()

    def find_line(pkg: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if f'"{pkg}"' in line:
                return idx
        return 1

    if isinstance(data, dict):
        for pkg, spec in data.get("dependencies", {}).items():
            deps.append(Dependency(pkg, str(spec), "npm", manifest_path, find_line(pkg), dev=False))
        for pkg, spec in data.get("devDependencies", {}).items():
            deps.append(Dependency(pkg, str(spec), "npm", manifest_path, find_line(pkg), dev=True))
        for pkg, spec in data.get("peerDependencies", {}).items():
            deps.append(Dependency(pkg, str(spec), "npm", manifest_path, find_line(pkg), dev=False))

    return deps


def _parse_requirements_txt(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Split out inline comments
        line = line.split("#")[0].strip()
        # Extract package name and specifier
        match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", line)
        if match:
            pkg = match.group(1).strip()
            spec = match.group(2).strip()
            deps.append(Dependency(pkg, spec, "pypi", manifest_path, line_no, dev=False))
    return deps


def _parse_pyproject_toml(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    lines = content.splitlines()

    def find_line(pkg: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if pkg in line:
                return idx
        return 1

    # PEP 621 dependencies
    project = data.get("project", {})
    if isinstance(project, dict):
        for req in project.get("dependencies", []):
            match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", req.strip())
            if match:
                pkg = match.group(1)
                deps.append(
                    Dependency(
                        pkg, match.group(2), "pypi", manifest_path, find_line(pkg), dev=False
                    )
                )

        opt_deps = project.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group, reqs in opt_deps.items():
                is_dev = "test" in group.lower() or "dev" in group.lower()
                for req in reqs:
                    match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", req.strip())
                    if match:
                        pkg = match.group(1)
                        deps.append(
                            Dependency(
                                pkg,
                                match.group(2),
                                "pypi",
                                manifest_path,
                                find_line(pkg),
                                dev=is_dev,
                            )
                        )

    # Poetry dependencies
    poetry = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict):
        for pkg, spec in poetry.get("dependencies", {}).items():
            if pkg.lower() != "python":
                deps.append(
                    Dependency(pkg, str(spec), "pypi", manifest_path, find_line(pkg), dev=False)
                )
        # Poetry groups
        groups = poetry.get("group", {})
        if isinstance(groups, dict):
            for group_name, gdata in groups.items():
                is_dev = "dev" in group_name.lower() or "test" in group_name.lower()
                for pkg, spec in gdata.get("dependencies", {}).items():
                    deps.append(
                        Dependency(
                            pkg, str(spec), "pypi", manifest_path, find_line(pkg), dev=is_dev
                        )
                    )

    return deps


def _parse_pipfile(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    lines = content.splitlines()

    def find_line(pkg: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if pkg in line:
                return idx
        return 1

    for pkg, spec in data.get("packages", {}).items():
        deps.append(Dependency(pkg, str(spec), "pypi", manifest_path, find_line(pkg), dev=False))
    for pkg, spec in data.get("dev-packages", {}).items():
        deps.append(Dependency(pkg, str(spec), "pypi", manifest_path, find_line(pkg), dev=True))
    return deps


def _parse_go_mod(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_block = False

    for line_no, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue

        if line == "require (":
            in_block = True
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            parts = line.split()
            if len(parts) >= 2:
                deps.append(
                    Dependency(parts[0], parts[1], "gomod", manifest_path, line_no, dev=False)
                )
        elif line.startswith("require "):
            parts = line[len("require ") :].strip().split()
            if len(parts) >= 2:
                deps.append(
                    Dependency(parts[0], parts[1], "gomod", manifest_path, line_no, dev=False)
                )

    return deps


def _parse_cargo_toml(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    lines = content.splitlines()

    def find_line(pkg: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if pkg in line:
                return idx
        return 1

    for pkg, spec in data.get("dependencies", {}).items():
        deps.append(Dependency(pkg, str(spec), "crates", manifest_path, find_line(pkg), dev=False))
    for pkg, spec in data.get("dev-dependencies", {}).items():
        deps.append(Dependency(pkg, str(spec), "crates", manifest_path, find_line(pkg), dev=True))

    return deps


def _parse_pom_xml(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return []

    # Namespace agnostic search
    for dep in root.iter():
        if dep.tag.endswith("dependency"):
            group_id = ""
            artifact_id = ""
            version = ""
            scope = ""
            for child in dep:
                tag = child.tag.split("}")[-1]
                if tag == "groupId" and child.text:
                    group_id = child.text.strip()
                elif tag == "artifactId" and child.text:
                    artifact_id = child.text.strip()
                elif tag == "version" and child.text:
                    version = child.text.strip()
                elif tag == "scope" and child.text:
                    scope = child.text.strip()

            if group_id and artifact_id:
                name = f"{group_id}:{artifact_id}"
                is_dev = scope.lower() in ("test", "provided")
                deps.append(Dependency(name, version, "maven", manifest_path, 1, dev=is_dev))

    return deps


def _parse_gradle(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    pattern = re.compile(
        r"""(?:implementation|api|compileOnly|testImplementation|testCompileOnly)\s*[\('"]+([^:'"]+):([^:'"]+):?([^'"\)]*)"""
    )
    for line_no, line in enumerate(content.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            group, artifact, version = m.groups()
            name = f"{group.strip()}:{artifact.strip()}"
            is_dev = "test" in line.lower()
            deps.append(
                Dependency(name, version.strip(), "maven", manifest_path, line_no, dev=is_dev)
            )
    return deps


def _parse_gemfile(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    pattern = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]*)['"])?""")
    for line_no, line in enumerate(content.splitlines(), start=1):
        m = pattern.match(line)
        if m:
            name, spec = m.groups()
            deps.append(Dependency(name, spec or "", "rubygems", manifest_path, line_no, dev=False))
    return deps


def _parse_composer_json(content: str, manifest_path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(content)
    except Exception:
        return []

    lines = content.splitlines()

    def find_line(pkg: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if f'"{pkg}"' in line:
                return idx
        return 1

    if isinstance(data, dict):
        for pkg, spec in data.get("require", {}).items():
            deps.append(
                Dependency(pkg, str(spec), "composer", manifest_path, find_line(pkg), dev=False)
            )
        for pkg, spec in data.get("require-dev", {}).items():
            deps.append(
                Dependency(pkg, str(spec), "composer", manifest_path, find_line(pkg), dev=True)
            )

    return deps
