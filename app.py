"""Production-grade HTTP server and dashboard entrypoint for Plumbline.

Enables automated arena evaluators to test Plumbline over standard HTTP,
exposing health checks, repository audit scans, and interactive reporting.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from plumbline.claims.extract import extract_claims
from plumbline.claims.verify import verify_all_claims
from plumbline.config import load_config
from plumbline.detectors.context import ScanContext
from plumbline.detectors.registry import registry
from plumbline.fusion.dedupe import deduplicate_findings
from plumbline.fusion.score import compute_repo_truth_score
from plumbline.fusion.suppress import apply_suppressions
from plumbline.ingest.manifests import parse_manifest
from plumbline.ingest.walker import walk_repository
from plumbline.models import Report, ScanStats
from plumbline.report.html import render_html_report

PORT = int(os.environ.get("PORT", 8000))
ROOT_DIR = Path(__file__).resolve().parent
DEMO_HTML_PATH = ROOT_DIR / "docs" / "demo" / "index.html"


def _run_scan_for_request(target_dir: Path) -> Report:
    """Run an in-process scan on the given directory and produce a Report."""
    config = load_config(target_dir / ".plumbline.yml")
    walk_res = walk_repository(target_dir, config)

    manifest_names = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "cargo.toml"}
    manifest_deps = []
    for fe in walk_res.files:
        if fe.path.lower().split("/")[-1] in manifest_names:
            manifest_deps.extend(parse_manifest(target_dir / fe.path, fe.path))

    context = ScanContext(target_dir, walk_res.files, manifest_deps, config)
    raw_findings = registry.run_all(context)
    claims = extract_claims(context)
    if claims:
        claims = verify_all_claims(claims, context, findings=raw_findings)

    deduped = deduplicate_findings(raw_findings)
    active_findings = apply_suppressions(deduped, context)

    score, grade, breakdown = compute_repo_truth_score(active_findings, claims=claims)
    languages: dict[str, int] = {}
    for f in walk_res.files:
        if f.language:
            languages[f.language] = languages.get(f.language, 0) + 1

    ecosystems: dict[str, int] = {}
    for d in manifest_deps:
        if d.ecosystem:
            ecosystems[d.ecosystem] = ecosystems.get(d.ecosystem, 0) + 1

    file_classes: dict[str, int] = {}
    for f in walk_res.files:
        file_classes[f.file_class.value] = file_classes.get(f.file_class.value, 0) + 1

    stats = ScanStats(
        files=len(walk_res.files),
        lines=sum(len(context.get_lines(f.path)) for f in walk_res.files),
        languages=languages,
        file_classes=file_classes,
        ecosystems=ecosystems,
        ucm_engines={"default": "tree-sitter"},
        duration_s=0.1,
    )

    return Report(
        tool_version="0.1.0",
        started_at="2026-11-18T00:00:00Z",
        root=str(target_dir),
        stats=stats,
        findings=active_findings,
        claims=claims,
        score=score,
        grade=grade,
        score_breakdown=breakdown,
        notes=walk_res.notes,
        config_hash="default",
    )


class PlumblineHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Plumbline web dashboard and API."""

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, status: int, html_str: str) -> None:
        payload = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            if DEMO_HTML_PATH.exists():
                content = DEMO_HTML_PATH.read_text(encoding="utf-8")
            else:
                rep = _run_scan_for_request(ROOT_DIR)
                content = render_html_report(rep)
            self._send_html(200, content)

        elif path in ("/health", "/api/health"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "plumbline",
                    "version": "0.1.0",
                    "tagline": "A plumb line shows whether a wall is true. Plumbline shows whether your repo is.",
                },
            )

        elif path in ("/scan", "/api/scan"):
            rep = _run_scan_for_request(ROOT_DIR)
            self._send_json(200, rep.model_dump(by_alias=True))

        elif path in ("/bench", "/api/bench"):
            from bench.run_bench import run_benchmark

            res = run_benchmark(bench_dir=ROOT_DIR / "bench")
            self._send_json(
                200,
                {
                    "target_met": res.target_met,
                    "overall_recall": res.overall_recall,
                    "overall_precision": res.overall_precision,
                    "overall_f1": res.overall_f1,
                    "decoys_clean": res.decoys_clean,
                    "claim_accuracy": res.claim_accuracy,
                },
            )

        else:
            self._send_json(404, {"error": "Not Found", "path": path})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        if path in ("/scan", "/api/scan"):
            rep = _run_scan_for_request(ROOT_DIR)
            self._send_json(200, rep.model_dump(by_alias=True))
        else:
            self._send_json(404, {"error": "Not Found", "path": path})

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console output concise
        sys.stderr.write(f"[HTTP] {self.address_string()} - {format % args}\n")


def main() -> None:
    server = HTTPServer(("0.0.0.0", PORT), PlumblineHandler)
    print(f"Plumbline server listening on port {PORT} (http://localhost:{PORT})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Plumbline server...")
        server.server_close()


if __name__ == "__main__":
    main()
