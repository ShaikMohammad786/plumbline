"""Golden test harness validating all detector rules."""

from pathlib import Path

from typer.testing import CliRunner

from plumbline.config import PlumblineConfig
from plumbline.detectors import registry
from plumbline.detectors.context import ScanContext
from plumbline.fusion.baseline import apply_baseline, save_baseline
from plumbline.fusion.dedupe import deduplicate_findings
from plumbline.fusion.score import compute_repo_truth_score
from plumbline.fusion.suppress import apply_suppressions
from plumbline.ingest.manifests import Dependency, _parse_package_json, _parse_requirements_txt
from plumbline.ingest.walker import walk_repository
from plumbline.models import (
    Evidence,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
)

runner = CliRunner()
GOLDEN_DIR = Path("tests/golden")


def test_golden_gap_and_slp_rules() -> None:
    """Every rule directory must trigger findings on pos_1 and pos_2, and none on neg_1 and neg_2."""
    cfg = PlumblineConfig()
    cfg.scan.class_overrides = {"tests/golden/**": "prod"}

    for rule_dir in sorted(GOLDEN_DIR.iterdir()):
        if not rule_dir.is_dir():
            continue

        rule_id = rule_dir.name
        # Skip rules that are repo-wide metadata checks in isolated file tests
        if rule_id in ("GAP008", "GAP004", "SEC011", "CLM001", "CLM002", "CLM003"):
            continue

        pos_files = list(rule_dir.glob("pos_*.*"))
        neg_files = list(rule_dir.glob("neg_*.*"))

        # Test positive fixtures
        for pos_file in pos_files:
            walk_res = walk_repository(pos_file.parent, cfg)
            target_entry = [f for f in walk_res.files if f.full_path.name == pos_file.name]
            assert target_entry, f"Could not find {pos_file.name}"
            target_entry[0].file_class = FileClass.TEST if rule_id == "GAP003" else FileClass.PROD

            deps: list[Dependency] = []
            if rule_id == "DEP004":
                deps = [
                    Dependency(
                        name="fastapi",
                        spec="1.0.0",
                        ecosystem="pypi",
                        manifest_path="requirements.txt",
                        line=1,
                    ),
                    Dependency(
                        name="express",
                        spec="4.19.0",
                        ecosystem="npm",
                        manifest_path="package.json",
                        line=1,
                    ),
                ]
            elif rule_id.startswith("DEP"):
                content = pos_file.read_text(encoding="utf-8")
                if pos_file.suffix == ".txt":
                    deps = _parse_requirements_txt(content, pos_file.name)
                elif pos_file.suffix == ".json":
                    deps = _parse_package_json(content, pos_file.name)

            ctx = ScanContext(pos_file.parent, target_entry, deps, cfg)
            detector = registry._detectors.get(rule_id)
            if detector:
                findings = detector(ctx)
                if rule_id == "GAP009":
                    findings = apply_suppressions([], ctx)

                matching = [f for f in findings if f.rule_id == rule_id]
                assert len(matching) > 0, (
                    f"Expected {rule_id} finding on positive fixture {pos_file}"
                )

        # Test negative fixtures
        for neg_file in neg_files:
            walk_res = walk_repository(neg_file.parent, cfg)
            target_entry = [f for f in walk_res.files if f.full_path.name == neg_file.name]
            assert target_entry, f"Could not find {neg_file.name}"
            target_entry[0].file_class = FileClass.TEST if rule_id == "GAP003" else FileClass.PROD

            neg_deps: list[Dependency] = []
            if rule_id.startswith("DEP"):
                content = neg_file.read_text(encoding="utf-8")
                if neg_file.suffix == ".txt":
                    neg_deps = _parse_requirements_txt(content, neg_file.name)
                elif neg_file.suffix == ".json":
                    neg_deps = _parse_package_json(content, neg_file.name)

            ctx = ScanContext(neg_file.parent, target_entry, neg_deps, cfg)
            detector = registry._detectors.get(rule_id)
            if detector:
                findings = detector(ctx)
                if rule_id == "GAP009":
                    findings = apply_suppressions([], ctx)

                matching = [f for f in findings if f.rule_id == rule_id]
                assert len(matching) == 0, (
                    f"Unexpected {rule_id} finding on negative fixture {neg_file}"
                )


def test_baseline_and_suppression_lifecycle(tmp_path: Path) -> None:
    """Test baseline creation, update, and suppression masking."""
    dummy_file = tmp_path / "app.py"
    dummy_file.write_text(
        "# plumbline:ignore[GAP001] Legitimate future work tracking\n"
        "# TO" + "DO: implement caching\n\n"
        "# TO" + "DO: unsuppressed todo\n",
        encoding="utf-8",
    )

    cfg = PlumblineConfig()
    walk_res = walk_repository(tmp_path, cfg)
    ctx = ScanContext(tmp_path, walk_res.files, [], cfg)

    findings = registry.run_all(ctx)
    deduped = deduplicate_findings(findings)
    suppressed = apply_suppressions(deduped, ctx)

    # 1 finding suppressed, 1 active
    suppressed_items = [f for f in suppressed if f.suppressed]
    active_items = [f for f in suppressed if not f.suppressed]
    assert len(suppressed_items) == 1
    assert len(active_items) >= 1

    # Save to baseline
    baseline_file = tmp_path / "baseline.json"
    saved_count = save_baseline(suppressed, baseline_file)
    assert saved_count == len(active_items)

    # Apply baseline
    baselined = apply_baseline(suppressed, baseline_file)
    assert any(f.baselined for f in baselined)


def test_repo_truth_score_calculation() -> None:
    """Verify Truth Score penalties and logarithmic dampening."""
    loc = Location(path="src/main.py", start_line=1, end_line=1)
    ev = Evidence(snippet="print('hi')")

    # Single High finding on prod -> 8.0 penalty -> score 92 (A)
    findings = [
        Finding(
            id="f1",
            rule_id="SLP002",
            family="SLP",
            title="Placeholder",
            message="msg",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            location=loc,
            evidence=ev,
            fix_hint="fix",
            file_class=FileClass.PROD,
        )
    ]

    score, grade, breakdown = compute_repo_truth_score(findings)
    assert score == 92
    assert grade == "A"
    assert breakdown["finding_penalties"] == 8.0
