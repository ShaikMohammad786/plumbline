# Plumbline

> *A plumb line shows whether a wall is true. Plumbline shows whether your repo is.*

Plumbline is an architecture-agnostic repository scanner, MCP server, and agent gate that finds security vulnerabilities, AI slop, coding gaps, and audits documentation claims against actual code evidence (**Claim Ledger**).

## Quickstart

```bash
# Install locally
pip install -e .

# Scan current repository
plumb scan .

# Check version
plumb version
```

## Features

- **Security Audits**: Detects hardcoded secrets, unsafe execution sinks, SQL injection, and insecure defaults.
- **AI Slop Detection**: Catches swallowed exceptions, placeholder data in production paths, dead code, and bloated functions.
- **Coding Gaps & Loose Ends**: Surfaces unfinished TODOs in security paths, stubs, unasserted tests, and missing environment documentation.
- **Claim Ledger**: Verifies capability claims made in README and docs against code evidence (`VERIFIED`, `PARTIAL`, `UNSUPPORTED`, `CONTRADICTED`).
- **Universal Code Model (UCM)**: Language-neutral fact representation powered by Tree-Sitter with lexical fallback.
- **Deterministic & Offline First**: Runs in seconds with zero API keys or external telemetry required.
- **Agent Integration**: Exposes stdio MCP server (`plumb mcp`) and pre-commit hooks (`plumb gate`).
