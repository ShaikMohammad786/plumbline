"""Plumbline CLI entrypoint."""

from __future__ import annotations

import datetime
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from plumbline.brain import reverify_claims, run_triage
from plumbline.claims.extract import extract_claims
from plumbline.claims.verify import verify_all_claims
from plumbline.config import load_config
from plumbline.detectors import registry
from plumbline.detectors.context import ScanContext
from plumbline.fusion.baseline import apply_baseline, save_baseline
from plumbline.fusion.dedupe import deduplicate_findings
from plumbline.fusion.score import compute_repo_truth_score
from plumbline.fusion.suppress import apply_suppressions
from plumbline.ingest.manifests import Dependency, parse_manifest
from plumbline.ingest.walker import walk_repository
from plumbline.models import FindingSeverity, Report, ScanStats
from plumbline.report.html import write_html_report
from plumbline.report.json_out import render_json_report
from plumbline.report.markdown import render_markdown_report, write_markdown_report
from plumbline.report.sarif import render_sarif_report
from plumbline.report.terminal import render_terminal_report

app = typer.Typer(
    name="plumb",
    help="Plumbline: Repository truth scanner for security, slop, gaps, and claim verification.",
    add_completion=False,
)
baseline_app = typer.Typer(help="Manage repository finding baselines.")
app.add_typer(baseline_app, name="baseline")

console = Console()
err_console = Console(stderr=True)

SEVERITY_THRESHOLDS = {
    "critical": {FindingSeverity.CRITICAL},
    "high": {FindingSeverity.CRITICAL, FindingSeverity.HIGH},
    "medium": {FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM},
    "low": {
        FindingSeverity.CRITICAL,
        FindingSeverity.HIGH,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
    },
    "none": set(),
}


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
    llm_provider: str = typer.Option(
        "compat", "--llm-provider", help="LLM provider (openai|anthropic|gemini|compat|mock)"
    ),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Model name"),
    llm_max_findings: int = typer.Option(25, "--llm-max-findings", help="Max findings to triage"),
    show_dismissed: bool = typer.Option(
        False, "--show-dismissed", help="Show findings dismissed by LLM"
    ),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Custom baseline JSON file"),
    no_claims: bool = typer.Option(
        False, "--no-claims", help="Skip claim ledger extraction and verification"
    ),
    diff: Optional[str] = typer.Option(
        None, "--diff", help="Only scan files changed relative to git ref"
    ),
    staged: bool = typer.Option(False, "--staged", help="Only scan staged files in git"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output"),
) -> None:
    """Scan repository for security vulnerabilities, AI slop, gaps, and claim verification."""
    start_time = time.perf_counter()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        cfg = load_config(fail_on=fail_on, online=online)
    except Exception as e:
        err_console.print(f"[bold red]Configuration error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    target_root = path.resolve()
    if not target_root.exists():
        err_console.print(f"[bold red]Path not found:[/bold red] {path}")
        raise typer.Exit(code=2)

    # 1. Ingest
    walk_result = walk_repository(target_root, cfg)
    files = walk_result.files
    notes = walk_result.notes

    if staged or diff:
        import subprocess

        changed: set[str] = set()
        cmd = (
            ["git", "diff", "--cached", "--name-only"]
            if staged
            else ["git", "diff", "--name-only", diff or "HEAD"]
        )
        try:
            res = subprocess.run(cmd, cwd=target_root, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.strip():
                        changed.add(line.strip().replace("\\", "/"))
        except Exception:
            pass
        if changed:
            files = [f for f in files if f.path in changed]

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

    # 2. Context & Facts
    context = ScanContext(
        root=target_root,
        files=files,
        dependencies=manifest_deps,
        config=cfg,
    )

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
            total_lines += len(f.text.splitlines())
            facts = context.get_facts(f.path)
            if facts and lang != "unknown" and lang not in ucm_engines:
                ucm_engines[lang] = facts.engine_used

    for dep in manifest_deps:
        ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1

    # 3. Detectors & Claims Execution
    raw_findings = registry.run_all(context)

    verified_claims = []
    if not no_claims:
        raw_claims = extract_claims(context)
        verified_claims = verify_all_claims(raw_claims, context, findings=raw_findings)

    # 4. Fusion Layer
    deduped = deduplicate_findings(raw_findings)
    suppressed = apply_suppressions(deduped, context)
    baselined = apply_baseline(suppressed, baseline)

    if llm:
        llm_cfg = cfg.llm.model_copy()
        if llm_provider != "compat":
            llm_cfg.provider = llm_provider
        if llm_model:
            llm_cfg.model = llm_model
        baselined = run_triage(baselined, context, llm_cfg, max_findings=llm_max_findings)
        if not no_claims and verified_claims:
            verified_claims = reverify_claims(verified_claims, context, llm_cfg)
        notes.append(f"LLM triage enabled (provider: {llm_cfg.provider}, model: {llm_cfg.model})")

    effective_findings = (
        baselined if show_dismissed else [f for f in baselined if not f.llm_dismissed]
    )
    score, grade, breakdown = compute_repo_truth_score(effective_findings, claims=verified_claims)

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

    report = Report(
        started_at=started_at,
        root=str(target_root),
        stats=stats,
        findings=baselined,
        claims=verified_claims,
        score=score,
        grade=grade,
        score_breakdown=breakdown,
        notes=notes,
    )

    # 5. Output formats
    if "json" in format:
        out_file = out / "report.json" if len(format) > 1 or out != Path(".plumbline/out") else None
        json_output = render_json_report(report, out_file)
        if not out_file and ("json" in format and len(format) == 1):
            console.print(json_output, soft_wrap=True, highlight=False)

    if "sarif" in format:
        out_file = (
            out / "report.sarif" if len(format) > 1 or out != Path(".plumbline/out") else None
        )
        sarif_output = render_sarif_report(report, out_file)
        if not out_file and ("sarif" in format and len(format) == 1):
            console.print(sarif_output, soft_wrap=True, highlight=False)

    if "md" in format or "markdown" in format:
        out_file = (
            out / "report.md"
            if len(format) > 1 or out != Path(".plumbline/out")
            else Path("PLUMBLINE_REPORT.md")
        )
        write_markdown_report(report, out_file)
        if not out_file and ("md" in format and len(format) == 1):
            console.print(render_markdown_report(report))

    if "html" in format:
        out_file = (
            out / "report.html"
            if len(format) > 1 or out != Path(".plumbline/out")
            else Path("report.html")
        )
        write_html_report(report, out_file)

    if "terminal" in format and not quiet:
        render_terminal_report(report, console)

    # 6. Exit code logic
    active_findings = [
        f
        for f in baselined
        if not f.suppressed and not f.baselined and (show_dismissed or not f.llm_dismissed)
    ]
    threshold_sevs = SEVERITY_THRESHOLDS.get(fail_on.lower(), SEVERITY_THRESHOLDS["high"])
    failing_findings = [f for f in active_findings if f.severity in threshold_sevs]

    if failing_findings:
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID to inspect, e.g. GAP001 or SLP001"),
) -> None:
    """Explain a detection rule with why it matters, examples, and remediation."""
    spec = registry.get(rule_id.upper())
    if not spec:
        err_console.print(f"[bold red]Unknown rule ID:[/bold red] {rule_id}")
        raise typer.Exit(code=2)

    console.print()
    title_text = f"[bold cyan]{spec.id}[/bold cyan]: {spec.title}"
    console.print(Panel(title_text, border_style="cyan"))

    console.print(f"[bold]Family:[/bold] {spec.family}")
    console.print(f"[bold]Default Severity:[/bold] {spec.severity.value}")
    console.print(f"[bold]Default Confidence:[/bold] {spec.confidence.value}")
    console.print(f"[bold]Heuristic:[/bold] {'Yes' if spec.heuristic else 'No'}")
    if spec.tags:
        console.print(f"[bold]Tags:[/bold] {', '.join(spec.tags)}")
    console.print(f"[bold]Fix Hint:[/bold] {spec.fix_hint}")
    console.print()

    console.print("[bold red]Bad Example:[/bold red]")
    console.print(Panel(spec.bad.strip(), border_style="red"))

    console.print("[bold green]Good Example:[/bold green]")
    console.print(Panel(spec.good.strip(), border_style="green"))

    console.print("[bold blue]How to Suppress:[/bold blue]")
    console.print(
        f"Add inline comment: [dim]// plumbline:ignore[{spec.id}] <mandatory reason>[/dim]"
    )
    console.print()


@app.command()
def rules(
    family: Optional[str] = typer.Option(
        None, "--family", "-f", help="Filter by rule family (GAP|SLP|SEC|DEP|CLM)"
    ),
    format: str = typer.Option("table", "--format", help="Output format (table|md)"),
) -> None:
    """List registered detection rules."""
    rule_list = registry.list_rules(family)

    if format == "md":
        for r in rule_list:
            console.print(f"- **{r.id}** ({r.severity.value}): {r.title}")
        return

    table = Table(title="Plumbline Detection Rules")
    table.add_column("ID", style="bold cyan")
    table.add_column("Family", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Confidence", style="white")
    table.add_column("Heuristic", style="dim")
    table.add_column("Title", style="white")

    for r in rule_list:
        h_str = "H" if r.heuristic else "-"
        table.add_row(r.id, r.family, r.severity.value, r.confidence.value, h_str, r.title)

    console.print(table)


@baseline_app.command("create")
def baseline_create(
    path: Path = typer.Argument(Path("."), help="Path to repository root"),
    out: Path = typer.Option(
        Path(".plumbline/baseline.json"), "--out", help="Baseline output path"
    ),
) -> None:
    """Create a new baseline JSON file from current scan findings."""
    cfg = load_config()
    walk_res = walk_repository(path.resolve(), cfg)
    ctx = ScanContext(path.resolve(), walk_res.files, [], cfg)
    raw = registry.run_all(ctx)
    deduped = deduplicate_findings(raw)
    suppressed = apply_suppressions(deduped, ctx)

    count = save_baseline(suppressed, out)
    console.print(f"[bold green]Baseline created:[/bold green] saved {count} findings to {out}")


@baseline_app.command("update")
def baseline_update(
    path: Path = typer.Argument(Path("."), help="Path to repository root"),
    out: Path = typer.Option(
        Path(".plumbline/baseline.json"), "--out", help="Baseline path to update"
    ),
) -> None:
    """Update baseline JSON file with current scan findings."""
    baseline_create(path, out)


hook_app = typer.Typer(help="Manage repository git hooks.")
app.add_typer(hook_app, name="hook")


@hook_app.command("install")
def hook_install(
    path: Path = typer.Option(Path("."), "--path", help="Repository root path"),
) -> None:
    """Install git pre-commit hook that runs plumb gate."""
    from plumbline.hooks import install_git_hook

    try:
        hook_file = install_git_hook(path)
        console.print(
            f"[bold green]✔ Git pre-commit hook installed successfully:[/bold green] {hook_file}"
        )
    except Exception as exc:
        err_console.print(f"[bold red]Failed to install git hook:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc


@app.command()
def gate(
    path: Path = typer.Argument(Path("."), help="Repository path"),
    fail_on: str = typer.Option("high", "--fail-on", help="Fail exit code threshold"),
    diff: Optional[str] = typer.Option(None, "--diff", help="Git ref to diff against"),
    staged: bool = typer.Option(
        True, "--staged/--all", help="Scan staged changes (default: staged)"
    ),
) -> None:
    """Compact gate scan for agents, subagents, and git pre-commit hooks."""
    target_root = path.resolve()
    try:
        cfg = load_config(fail_on=fail_on)
    except Exception as e:
        err_console.print(f"[bold red]Configuration error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    walk_res = walk_repository(target_root, cfg)
    files = walk_res.files

    if staged or diff:
        import subprocess

        changed: set[str] = set()
        cmd = (
            ["git", "diff", "--cached", "--name-only"]
            if staged
            else ["git", "diff", "--name-only", diff or "HEAD"]
        )
        try:
            res = subprocess.run(cmd, cwd=target_root, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.strip():
                        changed.add(line.strip().replace("\\", "/"))
        except Exception:
            pass

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
    for fe in walk_res.files:
        if fe.path.lower().split("/")[-1] in manifest_names:
            manifest_deps.extend(parse_manifest(target_root / fe.path, fe.path))

    context = ScanContext(target_root, walk_res.files, manifest_deps, cfg)
    raw_findings = registry.run_all(context)
    deduped = deduplicate_findings(raw_findings)
    suppressed = apply_suppressions(deduped, context)
    baselined = apply_baseline(suppressed, None)

    active_findings = [
        f for f in baselined if not f.suppressed and not f.baselined and not f.llm_dismissed
    ]
    if (staged or diff) and changed:
        active_findings = [f for f in active_findings if f.location.path in changed]
    threshold_sevs = SEVERITY_THRESHOLDS.get(fail_on.lower(), SEVERITY_THRESHOLDS["high"])
    failing = [f for f in active_findings if f.severity in threshold_sevs]

    if failing:
        console.print(
            f"[bold red]✖ Plumbline gate failed:[/bold red] {len(failing)} blocking finding(s) at or above '{fail_on}' threshold:"
        )
        for fnd in failing[:10]:
            console.print(
                f"  - [{fnd.severity.value.upper()}] [bold cyan]{fnd.rule_id}[/bold cyan] in {fnd.location.path}:{fnd.location.start_line} — {fnd.message}"
            )
        raise typer.Exit(code=1)

    console.print(
        f"[bold green]✔ Plumbline gate passed:[/bold green] 0 blocking findings (scanned {len(files)} files)."
    )
    raise typer.Exit(code=0)


@app.command()
def fix(
    path: Path = typer.Argument(Path("."), help="Repository path"),
    apply: bool = typer.Option(False, "--apply", help="Apply fixes directly to source files"),
    only: Optional[str] = typer.Option(None, "--only", help="Filter by rule ID, e.g. SEC005"),
) -> None:
    """Generate or apply safe auto-fix patches for SEC005, SLP007, DEP005."""
    from plumbline.report.patches import (
        SAFE_AUTOFIX_RULES,
        apply_patch_to_disk,
        generate_and_save_patches,
    )

    target_root = path.resolve()
    cfg = load_config()

    walk_res = walk_repository(target_root, cfg)
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
    for fe in walk_res.files:
        if fe.path.lower().split("/")[-1] in manifest_names:
            manifest_deps.extend(parse_manifest(target_root / fe.path, fe.path))

    context = ScanContext(target_root, walk_res.files, manifest_deps, cfg)
    raw_findings = registry.run_all(context)
    deduped = deduplicate_findings(raw_findings)
    suppressed = apply_suppressions(deduped, context)

    eligible = [
        f
        for f in suppressed
        if not f.suppressed
        and f.rule_id in SAFE_AUTOFIX_RULES
        and (not only or f.rule_id.upper() == only.upper())
    ]

    if not eligible:
        console.print(
            "[green]No safe autofixable findings detected (SEC005, SLP007, DEP005).[/green]"
        )
        return

    patches = generate_and_save_patches(eligible, target_root)
    if not patches:
        console.print(
            "[yellow]No applicable patches could be generated for eligible findings.[/yellow]"
        )
        return

    if apply:
        applied_count = 0
        for f_item, _diff, _ in patches:
            if apply_patch_to_disk(f_item, target_root):
                applied_count += 1
                console.print(
                    f"[bold green]✔ Applied autofix:[/bold green] {f_item.rule_id} in {f_item.location.path}:{f_item.location.start_line}"
                )
        console.print(f"[bold green]Successfully applied {applied_count} patch(es).[/bold green]")
    else:
        console.print(
            f"[bold cyan]Generated {len(patches)} patch(es) in .plumbline/fixes/ (dry-run):[/bold cyan]"
        )
        for f_item, diff_str, p_path in patches:
            console.print(
                f"\n[bold]{f_item.rule_id} in {f_item.location.path}:{f_item.location.start_line}[/bold] ({p_path})"
            )
            console.print(diff_str)
        console.print(
            "\n[dim]Run 'plumb fix --apply' to apply these patches directly to your files.[/dim]"
        )


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Repository path"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing configuration"),
) -> None:
    """Initialize .plumbline.yml configuration, git pre-commit hook, and CI workflow."""
    target_root = path.resolve()
    config_file = target_root / ".plumbline.yml"
    ci_file = target_root / ".github" / "workflows" / "plumbline.yml"

    if config_file.exists() and not force:
        console.print("[yellow].plumbline.yml already exists. Use --force to overwrite.[/yellow]")
    else:
        sample_config = (
            "version: 1\n\n"
            "scan:\n"
            "  include: []\n"
            "  exclude:\n"
            "    - '**/node_modules/**'\n"
            "    - '**/vendor/**'\n"
            "    - '**/.venv/**'\n"
            "  max_file_kb: 1024\n\n"
            "fail_on: high\n"
            "online: false\n\n"
            "llm:\n"
            "  provider: compat\n"
            "  model: gpt-4o\n"
            "  api_key_env: OPENAI_API_KEY\n"
            "  max_total_tokens: 100000\n"
            "  redact: true\n\n"
            "claims:\n"
            "  enabled: true\n"
            "  extra_sources: []\n\n"
            "report:\n"
            "  formats:\n"
            "    - terminal\n"
            "    - sarif\n"
            "    - html\n"
            "  out_dir: .plumbline/out\n"
        )
        config_file.write_text(sample_config, encoding="utf-8")
        console.print(f"[bold green]✔ Created configuration:[/bold green] {config_file}")

    # Write CI workflow
    ci_file.parent.mkdir(parents=True, exist_ok=True)
    if not ci_file.exists() or force:
        ci_content = (
            "name: Plumbline Scan\n\n"
            "on:\n"
            "  push:\n"
            "    branches: [main]\n"
            "  pull_request:\n"
            "    branches: [main]\n\n"
            "jobs:\n"
            "  plumbline:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/setup-python@v5\n"
            "        with:\n"
            "          python-version: '3.12'\n"
            "      - name: Install Plumbline\n"
            "        run: pip install .\n"
            "      - name: Run Plumbline Scan\n"
            "        run: plumb scan . --format terminal --format sarif --out .plumbline/out --fail-on high\n"
            "      - name: Upload SARIF report\n"
            "        if: always()\n"
            "        uses: github/codeql-action/upload-sarif@v3\n"
            "        with:\n"
            "          sarif_file: .plumbline/out/report.sarif\n"
        )
        ci_file.write_text(ci_content, encoding="utf-8")
        console.print(f"[bold green]✔ Created CI workflow:[/bold green] {ci_file}")

    # Try install git hook
    if (target_root / ".git").is_dir():
        from plumbline.hooks import install_git_hook

        try:
            h_path = install_git_hook(target_root)
            console.print(f"[bold green]✔ Installed git pre-commit hook:[/bold green] {h_path}")
        except Exception:
            pass


@app.command()
def mcp() -> None:
    """Start Plumbline stdio MCP server for AI coding agents."""
    from plumbline.mcp_server import run_mcp_server

    run_mcp_server()


@app.command()
def bench(
    bench_dir: Path = typer.Option(
        Path("bench"),
        "--bench-dir",
        "-b",
        help="Path to benchmark directory containing expected.json, victim, and victim-go.",
    ),
    out: Path = typer.Option(
        Path("bench/RESULTS.md"),
        "--out",
        "-o",
        help="Output markdown file for benchmark scorecard results.",
    ),
) -> None:
    """Run benchmark evaluation suite and output precision, recall, and F1."""
    from bench.run_bench import run_benchmark

    res = run_benchmark(bench_dir=bench_dir.resolve(), results_path=out.resolve(), console=console)
    if not res.target_met:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show Plumbline version information."""
    console.print("[bold]Plumbline[/bold] version 0.1.0")
    console.print("Python 3.11+ Universal Code Model & Repo Truth Scanner")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
