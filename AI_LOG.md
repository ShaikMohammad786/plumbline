# AI Development Log (AI_LOG.md)

This log provides a truthful, complete audit trail of all AI interactions, model selections, generated code, human/agent architectural modifications, rejections, and test verifications throughout the development of Plumbline.

---

## 2026-11-18 14:20 IST, Phase 0: Master Architecture & Planning
- **Tool and model**: Antigravity, Gemini 3.8 Flash (High)
- **Prompt summary**: Analyzed the Plumbline Master Brief, reviewed hackathon scoring requirements, established the 7-phase implementation strategy, non-negotiable engineering rules, and working agreements.
- **What the AI produced**:
  - Saved unchanging specification to `AGENTS.md` and `docs/BRIEF.md`.
  - Comprehensive 7-phase implementation plan artifact (`implementation_plan.md`) detailing the Universal Code Model, Claim Ledger taxonomy, 45 detector rules, benchmark methodology, and MCP gate.
  - Interactive Phase 1 plan artifact (`phase_1_plan.md`).
- **What I changed or rejected, and why**:
  - Rejected any upfront rule code generation until the base ingest and UCM infrastructure were verified.
  - Retained strict `arena.json` prompt requirement to seek human verification on official hackathon track schema before creating files with fabricated keys.
- **How it was verified**:
  - Verified local Python 3.12 availability using `uv`.
  - Verified local Git workspace initialization on `main` branch.
- **Open issues**:
  - Exact `arena.json` schema from the track brief pending user input.

---

## 2026-11-18 14:31 IST, Phase 1: Foundation, Ingest and Universal Code Model
- **Tool and model**: Antigravity, Gemini 3.8 Flash (High)
- **Prompt summary**: Implemented the repository skeleton, Pydantic v2 data models, configuration loader, directory walker with gitignore/size limits, language classifier, manifest parsers, UCM with Tree-Sitter queries and lexical fallback, CLI statistics, and multi-OS CI workflow.
- **What the AI produced**:
  - Package structure: `src/plumbline/{cli.py, config.py, models.py, mcp_server.py, hooks.py}`.
  - Ingest module: `ingest/walker.py`, `ingest/languages.py`, `ingest/manifests.py`, `ingest/classify.py`.
  - UCM module: `ucm/facts.py`, `ucm/builder.py`, `ucm/lexical.py`, and tree-sitter query files for Python, JS, TS, TSX, Go, Java in `ucm/queries/`.
  - Test suite: `tests/unit/test_models.py`, `tests/unit/test_config.py`, `tests/unit/test_ingest.py`, `tests/unit/test_ucm.py`, `tests/unit/test_cli.py`.
  - Multi-platform CI workflow: `.github/workflows/ci.yml`.
  - Scaffolding: `pyproject.toml`, `Makefile`, `README.md`.
- **What I changed or rejected, and why**:
  - Updated `builder.py` to adapt to modern Tree-Sitter 0.26+ `Query(grammar, pattern)` and `QueryCursor.captures` API rather than legacy dictionary bindings, guaranteeing fast native parsing for Python, JS, TS, Go, Java.
  - Updated `walker.py` from deprecated `gitwildmatch` to `gitignore` pattern spec in `pathspec`.
  - Added `B008` to ruff ignore to permit standard Typer argument and option function calls in CLI signatures.
  - Fixed `pathspec.PathSpec` generic type annotation to satisfy strict mypy checks.
- **How it was verified**:
  - `plumb version` and `plumb scan .` run cleanly in 0.09s.
  - `ruff check .` and `ruff format --check .` passed with 0 errors.
  - `mypy src tests` passed in strict mode with 0 errors.
  - `pytest --cov=src/plumbline` achieved 90% total test coverage across 20 unit tests.
  - Synthetic directory benchmark of 5,000 files verified under 5 seconds.
- **Open issues**:
  - None for Phase 1. Ready for Phase 2 (GAP and SLP detector rules, scoring, and reports).

---

## 2026-11-18 14:55 IST, Phase 2: Detectors (GAP & SLP), Fusion, Terminal & JSON Reports
- **Tool and model**: Antigravity, Gemini 3.8 Flash (High)
- **Prompt summary**: Implemented RuleSpec and centralized rule registry, ScanContext, 9 GAP detector rules, 10 SLP detector rules, fusion engine (SHA-256 stable fingerprinting, deduplication, inline suppressions with mandatory reasons, baseline create/update, logarithmic Repo Truth Scoring 0-100), Rich terminal and JSON reporting, and 19 golden test fixture sets.
- **What the AI produced**:
  - `src/plumbline/detectors/base.py`, `registry.py`, `context.py`.
  - `src/plumbline/detectors/gaps/rules.py` (GAP001 to GAP009).
  - `src/plumbline/detectors/slop/rules.py` (SLP001 to SLP010).
  - `src/plumbline/fusion/` (`fingerprint.py`, `dedupe.py`, `suppress.py`, `baseline.py`, `score.py`).
  - `src/plumbline/report/` (`terminal.py`, `json_out.py`).
  - CLI commands: `scan`, `rules`, `explain`, `baseline create|update`.
  - Generated documentation: `docs/RULES.md` and `docs/SCORING.md`.
  - Golden test harness `tests/unit/test_golden.py` and 19 fixture directories under `tests/golden/`.
  - Dogfooding configuration `.plumbline.yml`.
- **What I changed or rejected, and why**:
  - Fixed cross-platform Windows path handling: switched from `PurePosixPath` to `PurePath(path).as_posix()` in `walker.py`, `classify.py`, and `fingerprint.py` so Windows path separators `\` are correctly normalized to `/`.
  - Excluded `tests/golden` fixtures from project-wide linting and from default self-scan via `.plumbline.yml` because they deliberately contain broken/unreferenced code fixtures for testing detectors.
  - Refined `SLP002` placeholder detection to ignore detector rule definitions (e.g. `bad=`, `good=`, `RuleSpec(`) and keyword constants to prevent false positives during self-scanning.
  - Refined `SLP007` debug detector regex to `(?<!\.)\bprint\(` to prevent false positives on Rich `Console.print` method calls in the terminal renderer.
  - Refined `SLP010` identifier naming conflict detector to require `ident[0].islower()` for camelCase variables, preventing false positives on standard PascalCase class/type names (`FileClass`, `UserId`, `ScanContext`).
  - Restricted `GAP001` and `GAP002` to ignore markdown documentation (`FileClass.DOCS`) and restricted `GAP003` to test files (`FileClass.TEST`).
  - Improved `lexical.py` handler extraction to skip inline comments preceding `pass`/`return`.
- **How it was verified**:
  - Golden test suite passed across all 19 GAP and SLP rules with positive and negative fixtures.
  - `pytest --cov=src/plumbline` achieved 90% core coverage across 27 tests.
  - Strict typing (`mypy src tests`) and linting (`ruff check .`, `ruff format --check .`) passed with 0 errors.
  - Self-scan dogfooding: `plumb scan .` completed in 0.18s with Repo Truth Score 91/100 (Grade A), 0 Critical, 0 High, 0 Medium findings, and exit code 0.
  - Baseline lifecycle verified: `plumb baseline create` and baseline re-scan cleanly verified.
- **Open issues**:
  - Security (SEC001-SEC015) and Supply Chain (DEP001-DEP007) rules to be implemented in Phase 3.
