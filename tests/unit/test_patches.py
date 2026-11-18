"""Unit tests for safe autofix patch generation and application."""

from __future__ import annotations

from pathlib import Path

from plumbline.models import Evidence, Finding, FindingConfidence, FindingSeverity, Location
from plumbline.report.patches import (
    apply_patch_to_disk,
    generate_and_save_patches,
    generate_patch_for_finding,
)


def test_sec005_patch_generation(tmp_path: Path) -> None:
    test_file = tmp_path / "client.py"
    test_file.write_text(
        "import requests\nresponse = requests.get('https://example.com', verify=False)\n",
        encoding="utf-8",
    )

    finding = Finding(
        id="sec005patch0001",
        rule_id="SEC005",
        family="SEC",
        title="TLS verification disabled",
        message="TLS verification explicitly disabled with verify=False",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=Location(path="client.py", start_line=2, end_line=2),
        evidence=Evidence(snippet="verify=False"),
        fix_hint="Set verify=True",
    )

    res = generate_patch_for_finding(finding, tmp_path)
    assert res is not None
    rel_path, diff, new_content = res
    assert rel_path == "client.py"
    assert "-response = requests.get('https://example.com', verify=False)" in diff
    assert "+response = requests.get('https://example.com', verify=True)" in diff
    assert "verify=True" in new_content

    # Test applying to disk
    applied = apply_patch_to_disk(finding, tmp_path)
    assert applied is True
    assert "verify=True" in test_file.read_text(encoding="utf-8")


def test_slp007_debug_removal_patch(tmp_path: Path) -> None:
    test_file = tmp_path / "app.py"
    test_file.write_text(
        "def run():\n    print('debug leftover')\n    return 42\n",
        encoding="utf-8",
    )

    finding = Finding(
        id="slp007patch0002",
        rule_id="SLP007",
        family="SLP",
        title="Debug statement in production",
        message="print found in non-test code",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        location=Location(path="app.py", start_line=2, end_line=2),
        evidence=Evidence(snippet="print('debug leftover')"),
        fix_hint="Remove debug print statement",
    )

    res = generate_patch_for_finding(finding, tmp_path)
    assert res is not None
    rel_path, diff, new_content = res
    assert "-    print('debug leftover')" in diff
    assert "return 42" in new_content

    applied = apply_patch_to_disk(finding, tmp_path)
    assert applied is True
    updated = test_file.read_text(encoding="utf-8")
    assert "print('debug leftover')" not in updated
    assert "return 42" in updated


def test_dep005_unused_dependency_patch_requirements(tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\nunused-pkg>=1.0.0\nflask==3.0.0\n", encoding="utf-8")

    finding = Finding(
        id="dep005patch0003",
        rule_id="DEP005",
        family="DEP",
        title="Unused dependency",
        message="Declared dependency 'unused-pkg' is never imported",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.MEDIUM,
        location=Location(path="requirements.txt", start_line=2, end_line=2),
        evidence=Evidence(snippet="unused-pkg>=1.0.0"),
        fix_hint="Remove unused dependency",
    )

    res = generate_patch_for_finding(finding, tmp_path)
    assert res is not None
    _, diff, new_content = res
    assert "-unused-pkg>=1.0.0" in diff
    assert "requests==2.31.0" in new_content
    assert "flask==3.0.0" in new_content
    assert "unused-pkg" not in new_content


def test_generate_and_save_patches(tmp_path: Path) -> None:
    test_file = tmp_path / "api.py"
    test_file.write_text("import requests\nrequests.get(url, verify=False)\n", encoding="utf-8")

    finding = Finding(
        id="savepatch0000001",
        rule_id="SEC005",
        family="SEC",
        title="TLS verification disabled",
        message="TLS disabled",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=Location(path="api.py", start_line=2, end_line=2),
        evidence=Evidence(snippet="verify=False"),
        fix_hint="Enable verification",
    )

    fixes_dir = tmp_path / "fixes"
    saved = generate_and_save_patches([finding], tmp_path, out_dir=fixes_dir)
    assert len(saved) == 1
    assert (fixes_dir / "savepatch0000001.patch").exists()
