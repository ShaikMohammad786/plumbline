"""Unit tests for Plumbline MCP server tools (scan_path, scan_diff, check_done, explain_rule)."""

from __future__ import annotations

from pathlib import Path

from plumbline.mcp_server import check_done, explain_rule, scan_diff, scan_path


def test_mcp_explain_rule() -> None:
    res = explain_rule("SEC001")
    assert res.get("id") == "SEC001"
    assert "Hardcoded secret" in res.get("title", "")
    assert res.get("severity") == "critical"
    assert "plumbline:ignore[SEC001]" in res.get("suppression", "")

    # Invalid rule
    bad = explain_rule("INVALID_999")
    assert "error" in bad


def test_mcp_scan_path(tmp_path: Path) -> None:
    # Create simple python project
    src = tmp_path / "hello.py"
    src.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

    res = scan_path(path=str(tmp_path))
    assert "score" in res
    assert "grade" in res
    assert res["score"] >= 80
    assert "findings_count" in res


def test_mcp_check_done_clean(tmp_path: Path) -> None:
    code = tmp_path / "calc.py"
    code.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    res = check_done(
        task_summary="Add calculator function",
        changed_files=["calc.py"],
        path=str(tmp_path),
    )
    assert "done" in res
    assert res["done"] is True
    assert len(res["blockers"]) == 0
    assert len(res["next_steps"]) >= 1


def test_mcp_check_done_blocks_on_stub_or_high_issue(tmp_path: Path) -> None:
    # Plant a stub body (GAP002) in changed files
    stub = tmp_path / "auth_gate.py"
    stub.write_text("def verify_user_permissions(user):\n    pass\n", encoding="utf-8")

    res = check_done(
        task_summary="Implement auth permissions",
        changed_files=["auth_gate.py"],
        path=str(tmp_path),
    )
    assert res["done"] is False
    assert len(res["blockers"]) >= 1
    assert any("GAP002" in b or "HIGH" in b or "CRITICAL" in b for b in res["blockers"])


def test_mcp_scan_diff_clean() -> None:
    res = scan_diff()
    assert "score" in res
    assert "findings_count" in res
