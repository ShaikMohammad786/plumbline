"""Unit tests for Plumbline Brain: redaction, sandboxed tools, caching, provider, and triage loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plumbline.brain.cache import LLMCache
from plumbline.brain.loop import reverify_claims, run_triage
from plumbline.brain.provider import MockProvider
from plumbline.brain.redact import mask_secret_value, redact_secrets, wrap_untrusted
from plumbline.brain.tools import BrainToolSet
from plumbline.config import LLMConfig, PlumblineConfig
from plumbline.detectors.context import ScanContext
from plumbline.ingest.walker import walk_repository
from plumbline.models import (
    Claim,
    ClaimVerdict,
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
)


def test_mask_secret_value() -> None:
    assert mask_secret_value("short") == "shor****"
    # plumbline:ignore[SEC001] Unit test secret masking test value
    assert mask_secret_value("AKIAIOSFODNN7EXAMPLE") == "AKIA****************"
    assert mask_secret_value("abc") == "****"


# plumbline:ignore[SEC001] Unit test secret redaction test fixture
def test_redact_secrets_in_text() -> None:
    sample = (
        'api_key = "'
        + "super_secret_"
        + "access_token_12345"
        + '"\n'
        # plumbline:ignore[SEC001] Unit test secret redaction test fixture
        + 'aws_key = "'
        + "AKIA"
        + "1234567890ABCDEF"
        + '"\n'
        # plumbline:ignore[SEC001] Unit test secret redaction test fixture
        + 'gh_token = "'
        + "ghp_"
        + "1234567890abcdefghijklmnopqrstuvwxyzAB"
        + '"\n'
        + "-----BEGIN "
        + "PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n-----END "
        + "PRIVATE KEY-----\n"
    )
    redacted = redact_secrets(sample)
    assert "super_secret_" not in redacted
    assert ("AKIA" + "1234567890ABCDEF") not in redacted
    assert ("ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB") not in redacted
    assert "[REDACTED_PRIVATE_KEY_BLOCK]" in redacted
    assert "AKIA" in redacted  # First 4 chars preserved
    assert "api_key=" in redacted or 'api_key ="' in redacted or 'api_key="' in redacted


def test_wrap_untrusted() -> None:
    code = 'def test():\n    token = "secret123456789"'
    wrapped = wrap_untrusted(code)
    assert wrapped.startswith("<untrusted_code>\n")
    assert wrapped.endswith("\n</untrusted_code>")
    assert "secret123456789" not in wrapped


def test_sandboxed_tools_path_traversal_prevention(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    secret_file = tmp_path / "outside.txt"
    secret_file.write_text("outside secret", encoding="utf-8")

    toolset = BrainToolSet(repo)

    # Path traversal attempts must be blocked
    with pytest.raises(PermissionError):
        toolset.read_file("../outside.txt")

    with pytest.raises(PermissionError):
        toolset.list_dir("../../")


def test_sandboxed_tools_execution(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    sample_file = repo / "hello.py"
    sample_file.write_text(
        "def greet(name):\n    print('Hello ' + name)\n\ngreet('World')\n",
        encoding="utf-8",
    )

    toolset = BrainToolSet(repo)

    # 1. read_file
    res = toolset.read_file("hello.py", start=1, end=2)
    assert "<untrusted_code>" in res
    assert "def greet(name):" in res

    # 2. grep
    matches = toolset.grep("greet")
    assert len(matches) >= 1
    assert matches[0]["path"] == "hello.py"

    # 3. list_dir
    entries = toolset.list_dir(".")
    assert "hello.py" in entries

    # 4. execute_tool dispatch
    disp_res = toolset.execute_tool("read_file", {"path": "hello.py", "start": 1, "end": 1})
    assert "def greet" in disp_res


def test_llm_cache(tmp_path: Path) -> None:
    cache = LLMCache(cache_dir=tmp_path / "cache")
    key = LLMCache.compute_key({"test": 123})
    assert cache.get(key) is None

    cache.set(key, {"verdict": "confirm"})
    cached = cache.get(key)
    assert cached == {"verdict": "confirm"}


def test_triage_loop_mock_provider(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    src_file = repo / "auth.py"
    src_file.write_text("def login():\n    return False\n", encoding="utf-8")

    pconfig = PlumblineConfig()
    walk_res = walk_repository(repo, pconfig)
    ctx = ScanContext(repo, walk_res.files, [], pconfig)
    _ = ctx.get_facts("auth.py")

    # High severity finding
    f1 = Finding(
        id="f100000000000001",
        rule_id="SEC001",
        family="SEC",
        title="Hardcoded Secret",
        message="Contains hardcoded secret token",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=Location(path="auth.py", start_line=1, end_line=1),
        # plumbline:ignore[SEC001] Unit test evidence snippet
        evidence=Evidence(snippet="api_key = 'abcdef1234567890'"),
        fix_hint="Use env var",
    )

    # Low severity finding that can be dismissed
    f2 = Finding(
        id="f200000000000002",
        rule_id="SLP007",
        family="SLP",
        title="Debug statement",
        message="print statement found",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.LOW,
        location=Location(path="auth.py", start_line=2, end_line=2),
        evidence=Evidence(snippet="print('debug')"),
        fix_hint="Remove debug print",
    )

    # Provider dismissing everything
    mock = MockProvider(
        canned_responses=[
            {
                "content": json.dumps(
                    {"verdict": "dismiss", "rationale": "Intentional mock debug artifact"}
                ),
                "tool_calls": [],
                "usage": {"total_tokens": 100},
                "model": "mock-brain",
            },
            {
                "content": json.dumps(
                    {"verdict": "dismiss", "rationale": "Attempting to dismiss high finding"}
                ),
                "tool_calls": [],
                "usage": {"total_tokens": 100},
                "model": "mock-brain",
            },
        ]
    )

    cfg = LLMConfig(provider="mock", model="mock-brain")
    triaged = run_triage([f1, f2], ctx, cfg, provider=mock)

    # Finding 1 is HIGH severity with HIGH confidence -> CANNOT be auto-hidden
    assert triaged[0].llm is not None
    assert triaged[0].llm.verdict == "dismiss"
    assert triaged[0].llm_dismissed is False

    # Finding 2 is LOW severity -> CAN be auto-hidden
    assert triaged[1].llm is not None
    assert triaged[1].llm.verdict == "dismiss"
    assert triaged[1].llm_dismissed is True


def test_reverify_claims_mock_provider(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    pconfig = PlumblineConfig()
    walk_res = walk_repository(repo, pconfig)
    ctx = ScanContext(repo, walk_res.files, [], pconfig)

    c1 = Claim(
        id="c1",
        text="Provides offline scanning capabilities",
        source=Location(path="README.md", start_line=1, end_line=1),
        claim_type="offline",
        verdict=ClaimVerdict.PARTIAL,
        confidence=FindingConfidence.LOW,
    )

    mock = MockProvider(
        canned_responses=[
            {
                "content": json.dumps(
                    {
                        "verdict": "VERIFIED",
                        "confidence": "high",
                        "rationale": "Confirmed offline capabilities through documentation review.",
                    }
                ),
                "tool_calls": [],
                "usage": {"total_tokens": 80},
                "model": "mock-brain",
            }
        ]
    )

    cfg = LLMConfig(provider="mock", model="mock-brain")
    reverified = reverify_claims([c1], ctx, cfg, provider=mock)

    assert reverified[0].verdict == ClaimVerdict.VERIFIED
    assert reverified[0].method == "llm"
    assert reverified[0].confidence == FindingConfidence.HIGH


def test_toolset_advanced_coverage(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    code = repo / "app.py"
    code.write_text(
        "def calculate_total():\n    return 42\n\nval = calculate_total()\n", encoding="utf-8"
    )

    pconfig = PlumblineConfig()
    walk_res = walk_repository(repo, pconfig)
    ctx = ScanContext(repo, walk_res.files, [], pconfig)
    _ = ctx.get_facts("app.py")

    toolset = BrainToolSet(repo, ctx)

    # 1. find_symbol
    syms = toolset.find_symbol("calculate_total")
    assert len(syms) >= 1
    assert syms[0]["name"] == "calculate_total"

    # 2. find_references
    refs = toolset.find_references("calculate_total")
    assert len(refs) >= 1

    # 3. read_file invalid range
    res = toolset.read_file("app.py", start=999, end=1000)
    assert "exceeds file length" in res

    # 4. grep invalid regex
    err_grep = toolset.grep("[unclosed_regex")
    assert "Invalid regex" in err_grep[0].get("error", "")

    # 5. execute_tool unknown
    unk = toolset.execute_tool("non_existent_tool", {})
    assert "Unknown tool" in unk

    # 6. get_tool_definitions
    defs = BrainToolSet.get_tool_definitions()
    assert len(defs) == 5
    tool_names = [d["function"]["name"] for d in defs]
    assert "read_file" in tool_names
    assert "grep" in tool_names


def test_provider_factory() -> None:
    from plumbline.brain.provider import (
        AnthropicProvider,
        GeminiProvider,
        MockProvider,
        OpenAIProvider,
        create_provider,
    )

    assert isinstance(create_provider(LLMConfig(provider="mock")), MockProvider)
    assert isinstance(create_provider(LLMConfig(provider="openai")), OpenAIProvider)
    assert isinstance(create_provider(LLMConfig(provider="anthropic")), AnthropicProvider)
    assert isinstance(create_provider(LLMConfig(provider="gemini")), GeminiProvider)


def test_triage_downgrade(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    f = repo / "test.py"
    f.write_text("x = 1\n", encoding="utf-8")

    pconfig = PlumblineConfig()
    walk_res = walk_repository(repo, pconfig)
    ctx = ScanContext(repo, walk_res.files, [], pconfig)

    finding = Finding(
        id="f300000000000003",
        rule_id="SEC002",
        family="SEC",
        title="Eval statement",
        message="Dynamic eval",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=Location(path="test.py", start_line=1, end_line=1),
        evidence=Evidence(snippet="eval(x)"),
        fix_hint="Avoid eval",
    )

    mock = MockProvider(
        canned_responses=[
            {
                "content": json.dumps(
                    {"verdict": "downgrade", "rationale": "Controlled environment input"}
                ),
                "tool_calls": [],
                "usage": {"total_tokens": 50},
                "model": "mock-brain",
            }
        ]
    )

    cfg = LLMConfig(provider="mock", model="mock-brain")
    triaged = run_triage([finding], ctx, cfg, provider=mock)
    assert triaged[0].confidence == FindingConfidence.MEDIUM
