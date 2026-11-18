"""Plumbline CLI entrypoint."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from plumbline.config import load_config
from plumbline.ingest.manifests import Dependency, parse_manifest
from plumbline.ingest.walker import walk_repository
from plumbline.models import ScanStats
from plumbline.ucm.builder import extract_file_facts

app = typer.Typer(
    name="plumb",
    help="Plumbline: Repository truth scanner for security, slop, gaps, and claim verification.",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to repository root or directory to scan"),
    format: list[str] = typer.Option(
        ["terminal"], "--format", help="Output format (terminal|json|sarif|md|html)"
    ),
    out: Path = typer.Option(Path(".plumbline/out"), "--out", help="Output directory"),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Fail exit code threshold (critical|high|medium|low|none)"
    ),
    online: bool = typer.Option(False, "--online", help="Enable online registry lookups"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM triage and explanation"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output"),
) -> None:
    """Scan repository for security vulnerabilities, AI slop, gaps, and claim verification."""
    start_time = time.perf_counter()

    try:
        cfg = load_config(fail_on=fail_on, online=online)
    except Exception as e:
        err_console.print(f"[bold red]Configuration error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    target_root = path.resolve()
    if not target_root.exists():
        err_console.print(f"[bold red]Path not found:[/bold red] {path}")
        raise typer.Exit(code=2)

    if not quiet:
        console.print(f"[bold blue]Scanning repository:[/bold blue] {target_root}")

    # 1. Ingest: Walk files
    walk_result = walk_repository(target_root, cfg)
    files = walk_result.files
    notes = walk_result.notes

    # 2. Ingest: Parse manifests
    manifest_deps: list[Dependency] = []
    manifest_names = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "pipfile",
        "go.mod",
        "cargo.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gemfile",
        "composer.json",
    }

    for f in files:
        if Path(f.path).name.lower() in manifest_names or f.path.lower().startswith("requirements"):
            deps = parse_manifest(f.full_path, f.path)
            manifest_deps.extend(deps)

    # 3. UCM: Extract facts & record engines used
    languages: dict[str, int] = {}
    file_classes: dict[str, int] = {}
    ecosystems: dict[str, int] = {}
    ucm_engines: dict[str, str] = {}
    total_lines = 0

    for f in files:
        lang = f.language or "unknown"
        languages[lang] = languages.get(lang, 0) + 1

        cls_name = f.file_class.value
        file_classes[cls_name] = file_classes.get(cls_name, 0) + 1

        if f.text:
            lines = len(f.text.splitlines())
            total_lines += lines

            # Extract UCM facts
            facts = extract_file_facts(f.path, f.language, f.text)
            if lang != "unknown" and lang not in ucm_engines:
                ucm_engines[lang] = facts.engine_used

    for dep in manifest_deps:
        ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1

    duration = time.perf_counter() - start_time

    stats = ScanStats(
        files=len(files),
        lines=total_lines,
        languages=languages,
        file_classes=file_classes,
        ecosystems=ecosystems,
        ucm_engines=ucm_engines,
        duration_s=round(duration, 3),
    )

    if not quiet:
        # Display Stats Table
        table = Table(title="[bold cyan]Plumbline Repository Ingest & UCM Summary[/bold cyan]")
        table.add_column("Metric", style="bold white")
        table.add_column("Value", style="green")

        table.add_row("Total Files Ingested", str(stats.files))
        table.add_row("Total Lines of Code", str(stats.lines))
        table.add_row(
            "Languages Detected", ", ".join(f"{k} ({v})" for k, v in sorted(languages.items()))
        )
        table.add_row(
            "File Classes", ", ".join(f"{k}: {v}" for k, v in sorted(file_classes.items()))
        )
        table.add_row(
            "Dependencies Found", f"{len(manifest_deps)} across {len(ecosystems)} ecosystems"
        )
        if ecosystems:
            table.add_row(
                "Ecosystems", ", ".join(f"{k} ({v})" for k, v in sorted(ecosystems.items()))
            )
        table.add_row(
            "UCM Parsing Engines", ", ".join(f"{k} -> {v}" for k, v in sorted(ucm_engines.items()))
        )
        table.add_row("Scan Duration", f"{stats.duration_s:.3f} seconds")

        console.print(table)

        if notes and verbose:
            console.print("\n[bold yellow]Scan Notes:[/bold yellow]")
            for note in notes:
                console.print(f"  • {note}")

        console.print(
            "\n[bold green]Scan completed clean: 0 findings (Phase 1 Foundation)[/bold green]"
        )

    # Exit code: 0 clean
    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    """Show Plumbline version information."""
    console.print("[bold]Plumbline[/bold] version 0.1.0")
    console.print("Python 3.11+ Universal Code Model & Repo Truth Scanner")


@app.command()
def rules(
    family: Optional[str] = typer.Option(
        None, "--family", "-f", help="Filter by rule family (SEC|DEP|SLP|GAP|CLM)"
    ),
    format: str = typer.Option("table", "--format", help="Output format (table|md)"),
) -> None:
    """List registered detection rules."""
    table = Table(title="Plumbline Detection Rules")
    table.add_column("ID", style="bold cyan")
    table.add_column("Family", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="white")

    # In Phase 1, the rule registry is empty
    console.print(table)
    console.print("[dim]No rules loaded in Phase 1 (foundation). Rules activate in Phase 2.[/dim]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
