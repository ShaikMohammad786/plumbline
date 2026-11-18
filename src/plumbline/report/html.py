"""Single-file standalone HTML report generator.

Zero external dependencies, zero network requests, file:// friendly.
Features SVG score ring, multi-dimensional filters, instant search, and claim ledger.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Optional

from plumbline.models import Report


def _escape(text: str) -> str:
    return html.escape(str(text))


def render_html_report(report: Report) -> str:
    """Render a standalone, self-contained HTML report with inline CSS and JS."""
    # Findings JSON for client-side search and filtering
    findings_data = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "family": f.family,
            "title": f.title,
            "message": f.message,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "path": f.location.path,
            "start_line": f.location.start_line,
            "end_line": f.location.end_line,
            "snippet": f.evidence.snippet,
            "fix_hint": f.fix_hint,
        }
        for f in report.findings
    ]

    claims_data = [
        {
            "id": c.id,
            "text": c.text,
            "type": c.claim_type,
            "verdict": c.verdict.value,
            "path": c.source.path,
            "line": c.source.start_line,
            "evidence": c.evidence,
        }
        for c in report.claims
    ]

    # Score color mapping
    score = report.score
    if score >= 90:
        score_color = "#10b981"  # emerald
    elif score >= 80:
        score_color = "#3b82f6"  # blue
    elif score >= 70:
        score_color = "#f59e0b"  # amber
    elif score >= 60:
        score_color = "#f97316"  # orange
    else:
        score_color = "#ef4444"  # red

    # SVG stroke dash calculation for circle (circumference 2 * pi * 52 = ~326.7)
    circumference = 326.72
    stroke_dashoffset = circumference - (circumference * score / 100)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Plumbline Report - {_escape(report.root)}</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --info: #6b7280;
      --verified: #10b981;
      --partial: #f59e0b;
      --unsupported: #ef4444;
      --contradicted: #991b1b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      line-height: 1.5;
      padding: 2rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1.5rem;
    }}
    .header-title h1 {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
    .header-title p {{ color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }}
    .score-card {{
      display: flex;
      align-items: center;
      gap: 1.5rem;
      background: var(--card-bg);
      padding: 1rem 1.5rem;
      border-radius: 12px;
      border: 1px solid var(--card-border);
    }}
    .ring-container {{ position: relative; width: 120px; height: 120px; }}
    .ring-svg {{ transform: rotate(-90deg); width: 120px; height: 120px; }}
    .ring-bg {{ fill: none; stroke: #1f2937; stroke-width: 10; }}
    .ring-progress {{
      fill: none;
      stroke: {score_color};
      stroke-width: 10;
      stroke-linecap: round;
      stroke-dasharray: {circumference:.2f};
      stroke-dashoffset: {stroke_dashoffset:.2f};
      transition: stroke-dashoffset 1s ease;
    }}
    .ring-text {{
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }}
    .ring-score {{ font-size: 1.6rem; font-weight: 800; color: #fff; }}
    .ring-grade {{ font-size: 0.9rem; font-weight: 600; color: {score_color}; }}
    .stats-summary {{ display: flex; flex-direction: column; gap: 0.4rem; }}
    .stat-pill {{ font-size: 0.85rem; color: var(--text-muted); }}
    .stat-pill strong {{ color: #fff; }}

    /* Filters Bar */
    .controls-panel {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
      margin-bottom: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .search-input {{
      width: 100%;
      padding: 0.75rem 1rem;
      background: #0d131f;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      color: #fff;
      font-size: 0.95rem;
      outline: none;
    }}
    .search-input:focus {{ border-color: var(--primary); }}
    .filter-group {{ display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}
    .filter-label {{ font-size: 0.85rem; font-weight: 600; color: var(--text-muted); min-width: 80px; }}
    .filter-btn {{
      background: #0d131f;
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 0.35rem 0.85rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.15s ease;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background: var(--primary);
      color: #fff;
      border-color: var(--primary);
    }}

    /* Findings Grid */
    .section-title {{
      font-size: 1.3rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .findings-list {{ display: flex; flex-direction: column; gap: 1rem; margin-bottom: 3rem; }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
      border-left: 4px solid var(--info);
      transition: transform 0.1s ease;
    }}
    .finding-card.critical {{ border-left-color: var(--critical); }}
    .finding-card.high {{ border-left-color: var(--high); }}
    .finding-card.medium {{ border-left-color: var(--medium); }}
    .finding-card.low {{ border-left-color: var(--low); }}
    .finding-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.5rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .loc-tag {{ font-family: monospace; font-size: 0.85rem; color: #60a5fa; }}
    .finding-title {{ font-size: 1.05rem; font-weight: 600; color: #fff; margin-bottom: 0.4rem; }}
    .finding-msg {{ font-size: 0.9rem; color: var(--text-muted); margin-bottom: 0.75rem; }}
    .code-snippet {{
      background: #090d16;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.85rem;
      color: #e5e7eb;
      overflow-x: auto;
      border: 1px solid #1e293b;
      margin-bottom: 0.75rem;
    }}
    .fix-box {{
      font-size: 0.85rem;
      color: #34d399;
      background: rgba(16, 185, 129, 0.08);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      border-left: 3px solid #10b981;
    }}

    /* Claim Ledger Table */
    .table-container {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      overflow-x: auto;
      margin-bottom: 3rem;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
    th, td {{ padding: 0.85rem 1rem; border-bottom: 1px solid var(--card-border); }}
    th {{ background: #0d131f; color: var(--text-muted); font-weight: 600; }}
    tr:last-child td {{ border-bottom: none; }}
    .badge-verdict {{ font-size: 0.75rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 4px; }}
    .verdict-verified {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }}
    .verdict-partial {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
    .verdict-unsupported {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
    .verdict-contradicted {{ background: rgba(153, 27, 27, 0.4); color: #fca5a5; border: 1px solid #ef4444; }}

    footer {{ text-align: center; color: var(--text-muted); font-size: 0.85rem; padding: 2rem 0; border-top: 1px solid var(--card-border); }}

    @media print {{
      body {{ background: #fff; color: #000; padding: 0; }}
      .controls-panel {{ display: none; }}
      .finding-card, .table-container, .score-card {{ border: 1px solid #ccc; background: #fff; color: #000; }}
      .code-snippet {{ background: #f5f5f5; color: #000; border: 1px solid #ddd; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-title">
        <h1>Plumbline Repository Audit</h1>
        <p>Path: <code>{_escape(report.root)}</code> &bull; Scanned: {_escape(str(report.started_at)[:19])}</p>
      </div>
      <div class="score-card">
        <div class="ring-container">
          <svg class="ring-svg" viewBox="0 0 120 120">
            <circle class="ring-bg" cx="60" cy="60" r="52"></circle>
            <circle class="ring-progress" cx="60" cy="60" r="52"></circle>
          </svg>
          <div class="ring-text">
            <div class="ring-score">{score}</div>
            <div class="ring-grade">Grade {report.grade}</div>
          </div>
        </div>
        <div class="stats-summary">
          <div class="stat-pill">Files scanned: <strong>{report.stats.files}</strong> ({report.stats.lines} lines)</div>
          <div class="stat-pill">Duration: <strong>{report.stats.duration_s:.2f}s</strong></div>
          <div class="stat-pill">Active findings: <strong>{len(report.findings)}</strong></div>
          <div class="stat-pill">Claims audited: <strong>{len(report.claims)}</strong></div>
        </div>
      </div>
    </header>

    <div class="controls-panel">
      <input type="text" id="searchInput" class="search-input" placeholder="Live search by rule, message, file, or snippet..." autocomplete="off">
      <div class="filter-group" id="familyFilters">
        <span class="filter-label">Family:</span>
        <button class="filter-btn active" data-family="ALL">ALL</button>
        <button class="filter-btn" data-family="SEC">SEC</button>
        <button class="filter-btn" data-family="DEP">DEP</button>
        <button class="filter-btn" data-family="SLP">SLP</button>
        <button class="filter-btn" data-family="GAP">GAP</button>
        <button class="filter-btn" data-family="CLM">CLM</button>
      </div>
      <div class="filter-group" id="severityFilters">
        <span class="filter-label">Severity:</span>
        <button class="filter-btn active" data-sev="ALL">ALL</button>
        <button class="filter-btn" data-sev="critical">CRITICAL</button>
        <button class="filter-btn" data-sev="high">HIGH</button>
        <button class="filter-btn" data-sev="medium">MEDIUM</button>
        <button class="filter-btn" data-sev="low">LOW</button>
      </div>
    </div>

    <div class="section-title">
      <span>Findings</span>
      <span id="findingsCounter" style="font-size: 0.95rem; font-weight: normal; color: var(--text-muted);">{len(report.findings)} shown</span>
    </div>

    <div class="findings-list" id="findingsContainer">
      <!-- Injected by client script -->
    </div>

    <div class="section-title">
      <span>Claim Ledger (Documentation vs Code Reality)</span>
      <span style="font-size: 0.95rem; font-weight: normal; color: var(--text-muted);">{len(report.claims)} claims</span>
    </div>

    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Verdict</th>
            <th>Category</th>
            <th>Documented Claim</th>
            <th>Source Location</th>
            <th>Code Evidence</th>
          </tr>
        </thead>
        <tbody id="claimsTableBody">
          <!-- Injected by client script -->
        </tbody>
      </table>
    </div>

    <footer>
      Plumbline Repo Audit &bull; A plumb line shows whether a wall is true. Plumbline shows whether your repo is.
    </footer>
  </div>

  <script>
    const findingsData = {json.dumps(findings_data)};
    const claimsData = {json.dumps(claims_data)};

    let activeFamily = "ALL";
    let activeSeverity = "ALL";
    let searchQuery = "";

    function renderFindings() {{
      const container = document.getElementById("findingsContainer");
      const filtered = findingsData.filter(f => {{
        if (activeFamily !== "ALL" && f.family !== activeFamily) return false;
        if (activeSeverity !== "ALL" && f.severity !== activeSeverity) return false;
        if (searchQuery) {{
          const target = (f.rule_id + " " + f.title + " " + f.message + " " + f.path + " " + f.snippet).toLowerCase();
          if (!target.includes(searchQuery)) return false;
        }}
        return true;
      }});

      document.getElementById("findingsCounter").textContent = `${{filtered.length}} of ${{findingsData.length}} shown`;

      if (filtered.length === 0) {{
        container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 3rem;">No matching findings found.</div>';
        return;
      }}

      container.innerHTML = filtered.map(f => `
        <div class="finding-card ${{f.severity}}">
          <div class="finding-header">
            <div>
              <span class="badge badge-${{f.severity}}">${{f.severity}}</span>
              <strong style="margin-left: 0.5rem; color: #fff;">${{f.rule_id}}</strong> &bull; ${{f.family}}
            </div>
            <span class="loc-tag">${{f.path}}:${{f.start_line}}</span>
          </div>
          <div class="finding-title">${{f.title}}</div>
          <div class="finding-msg">${{f.message}}</div>
          ${{f.snippet ? `<pre class="code-snippet"><code>${{escapeHtml(f.snippet)}}</code></pre>` : ''}}
          ${{f.fix_hint ? `<div class="fix-box"><strong>Fix Hint:</strong> ${{escapeHtml(f.fix_hint)}}</div>` : ''}}
        </div>
      `).join("");
    }}

    function renderClaims() {{
      const tbody = document.getElementById("claimsTableBody");
      if (claimsData.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No documentation claims extracted.</td></tr>';
        return;
      }}
      tbody.innerHTML = claimsData.map(c => {{
        const verdictClass = "verdict-" + c.verdict.toLowerCase();
        const evHtml = c.evidence && c.evidence.length > 0
          ? c.evidence.map(e => `<div><code>${{e.path || ''}}:${{e.line || 1}}</code> (${{escapeHtml(e.note || '')}})</div>`).join("")
          : '<em>No evidence</em>';

        return `
          <tr>
            <td><span class="badge-verdict ${{verdictClass}}">${{c.verdict}}</span></td>
            <td><code>${{c.type}}</code></td>
            <td><strong>${{escapeHtml(c.text)}}</strong></td>
            <td><code>${{c.path}}:${{c.line}}</code></td>
            <td style="font-size: 0.85rem;">${{evHtml}}</td>
          </tr>
        `;
      }}).join("");
    }}

    function escapeHtml(str) {{
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }}

    // Event listeners
    document.querySelectorAll("#familyFilters button").forEach(btn => {{
      btn.addEventListener("click", () => {{
        document.querySelectorAll("#familyFilters button").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        activeFamily = btn.dataset.family;
        renderFindings();
      }});
    }});

    document.querySelectorAll("#severityFilters button").forEach(btn => {{
      btn.addEventListener("click", () => {{
        document.querySelectorAll("#severityFilters button").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        activeSeverity = btn.dataset.sev;
        renderFindings();
      }});
    }});

    document.getElementById("searchInput").addEventListener("input", (e) => {{
      searchQuery = e.target.value.toLowerCase().trim();
      renderFindings();
    }});

    // Initial render
    renderFindings();
    renderClaims();
  </script>
</body>
</html>
"""
    return html_content


def write_html_report(report: Report, out_path: Optional[Path] = None) -> Path:
    """Render and write report to a standalone HTML file."""
    if out_path is None:
        out_path = Path("index.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_html_report(report)
    out_path.write_text(content, encoding="utf-8")
    return out_path
