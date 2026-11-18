# Plumbline: 3-Minute Hackathon Demo & Video Walkthrough Script

**Tagline**: *"A plumb line shows whether a wall is true. Plumbline shows whether your repo is."*  
**Presenter**: Lead Engineer, Plumbline  
**Target Video Duration**: 3:00 minutes (180 seconds)  

---

## Shot List & Narrative Timeline

```mermaid
timeline
    title 3-Minute Plumbline Walkthrough
    00:00 - 00:30 : The Hook & The AI Code Crisis
    00:30 - 01:15 : Core Architecture & 5 Truth Pillars
    01:15 - 02:00 : Live Scan & Interactive Claim Ledger
    02:00 - 02:30 : Agent Done-Gate & Safe Auto-Fix
    02:30 - 03:00 : Measured Benchmarks & Closing
```

---

### Segment 1: The Hook & The Problem (0:00 - 0:30 | 30s)

**Visuals**:
- Camera on presenter, transitioning to screen recording of modern terminal showing an AI-agent generated pull request.
- Highlight common AI agent issues: hallucinated packages, skipped exceptions, stubs returning literals.

**Spoken Dialogue**:
> "Engineering teams are writing code faster than ever using AI coding agents. But speed without truth is a disaster. Recent research shows that over 80% of agent-assisted PRs introduce hidden vulnerabilities, hallucinated package dependencies, empty exception catchers, or fake stubs.
>
> Even worse: the agent writes a glowing `README.md` claiming JWT authentication, AES encryption, and automated testing—while the code has zero tests and disabled TLS verification.
> 
> How do you know if your repository is actually true?
> 
> In construction, a plumb line uses gravity to prove if a wall is vertically true. **Plumbline** shows whether your repo is."

---

### Segment 2: Architecture & Philosophy (0:30 - 1:15 | 45s)

**Visuals**:
- Split-screen diagram: Language Source Files $\to$ Universal Code Model (UCM) $\to$ 5 Detector Families $\to$ Fusion $\to$ Claim Ledger.
- Display CLI installation: `pipx install .` (Zero API key, zero network, zero build step).

**Spoken Dialogue**:
> "Plumbline is an architecture-agnostic repository auditor and AI truth scanner.
>
> It requires **no build step**, **no API key**, and operates **100% offline by default**.
>
> At its core is our **Universal Code Model (UCM)**. Using Tree-Sitter grammars and high-speed lexical fallbacks, Plumbline extracts universal code facts—symbols, call graphs, exception handlers, string literals, and route endpoints—across Python, JavaScript, TypeScript, Go, Dockerfiles, and CI workflows.
>
> Five rule engines audit every line:
> 1. **SEC**: Hardcoded secrets, SQL injection, unsafe deserialization, prompt injection.
> 2. **DEP**: Hallucinated packages and typo-squatted dependencies.
> 3. **SLP**: AI slop—swallowed exceptions, dummy mock data in production, and tautological comments.
> 4. **GAP**: Forgotten TODOs near auth, empty stub bodies, and untested modules.
> 5. **CLM**: The **Claim Ledger**—extracting every promise in your documentation and auditing whether the code actually backs it up."

---

### Segment 3: Live Scan & The Claim Ledger (1:15 - 2:00 | 45s)

**Visuals**:
- Terminal running: `plumb scan bench/victim`
- Rich terminal output with score ring (0/100, Grade F) and findings table.
- Switching to browser tab: `docs/demo/index.html` (interactive score, filter tabs, evidence snippets).

**Spoken Dialogue**:
> "Let’s run Plumbline on `vibe-shop`—a multi-language microservice with planted vulnerabilities.
> 
> `[Presenter types: plumb scan bench/victim]`
> 
> In less than 100 milliseconds, Plumbline scans the entire repository offline.
> 
> Look at the **Repo Truth Score**: 0/100, Grade F.
> 
> It caught an unmasked Stripe secret key, SQL injection in `db.py`, and `requests.post(..., verify=False)` in payment processing.
> 
> But look below at the **Claim Ledger**. The README promised 'Strict TLS verification on payment requests'—Plumbline marked it **CONTRADICTED** because line 32 in `payments.py` disables TLS! It promised 'Redis caching'—marked **UNSUPPORTED** because zero caching imports exist.
> 
> Every finding is exported into an interactive, zero-network HTML report with full evidence snippets and fix hints."

---

### Segment 4: Agent Done-Gate & Safe Auto-Fix (2:00 - 2:30 | 30s)

**Visuals**:
- Terminal showing: `plumb gate` and `plumb mcp` integration with Cursor/Claude Code.
- Displaying JSON response of `check_done` tool with `done: false` and blocker list.
- Terminal running: `plumb fix --apply` and git diff showing auto-fixed lines.

**Spoken Dialogue**:
> "Plumbline isn't just for human developers; it’s built for AI agents.
> 
> Through our official **stdio MCP server**, agents can invoke `check_done` on their active worktree. If an agent tries to mark a task complete while leaving behind high-severity bugs, stubbed implementations (`GAP002`), or unverified claims (`CLM004`), `check_done` halts the agent and gives it exact next steps.
> 
> For common mechanical issues like unpinned dependencies, debug logs, or disabled TLS verification, `plumb fix --apply` automatically generates and applies verified unified diff patches."

---

### Segment 5: Measured Benchmark Truth & Closing (2:30 - 3:00 | 30s)

**Visuals**:
- Terminal running: `plumb bench`
- Benchmark table in green: 100% Recall, 87.6% Precision, 20/20 Clean Decoys.
- Closing slide with GitHub repository URL, MIT License, and arena badges.

**Spoken Dialogue**:
> "How do we prove Plumbline works without cheating?
> 
> `[Presenter types: plumb bench]`
> 
> Our benchmark suite tests Plumbline against 80 planted issues and 20 deliberate negative decoys across Python and Go.
> 
> Result: **100.0% Recall**, **87.6% Precision**, **93.4% F1 Score**, and **20 out of 20 decoys clean**—running in 0.09 seconds.
> 
> Plumbline is open-source, fully typed, dogfooded with zero high findings on itself, and installs in seconds.
> 
> Never trust unverified AI code again. Keep your repository true with Plumbline."
