# Plumbline Benchmark Evaluation Results

**Test Date & Time**: 2026-11-18 10:55:26 UTC
**Scan Engine**: Plumbline Universal Code Model (UCM) & Deterministic Fusion
**Execution Duration**: 0.045 seconds
**Overall Status**: ✅ PASSED (Targets Met: Precision >= 0.85, Recall >= 0.85)

---

## 1. Overall Performance Summary

| Metric | Measured Score | Benchmark Target | Verdict |
| :--- | :--- | :--- | :--- |
| **Overall Precision** | **86.7%** (0.867) | $\ge 85.0\%$ | ✅ PASS |
| **Overall Recall** | **100.0%** (1.000) | $\ge 85.0\%$ | ✅ PASS |
| **Harmonic Mean (F1)** | **92.9%** (0.929) | $\ge 85.0\%$ | ✅ PASS |
| **Decoy Precision** | **20/20 (100.0%)** | $100.0\%$ | ✅ PASS |
| **Claim Ledger Accuracy** | **12/12 (100.0%)** | $\ge 80.0\%$ | ✅ PASS |

---

## 2. Per-Family Breakdown

| Rule Family | Description | Planted Issues | Detected (TP) | Missed (FN) | False Pos (FP) | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC** | Security Vulnerabilities & Secrets | 18 | 18 | 0 | 1 | 0.947 | 1.000 | **0.973** |
| **DEP** | Supply Chain & Dependency Hallucinations | 15 | 15 | 0 | 3 | 0.833 | 1.000 | **0.909** |
| **SLP** | AI Slop, Placeholders & Code Quality | 15 | 15 | 0 | 1 | 0.938 | 1.000 | **0.968** |
| **GAP** | Loose Ends, Untested Modules & Stubs | 21 | 21 | 0 | 3 | 0.875 | 1.000 | **0.933** |
| **CLM** | Claim Ledger Documentation Inconsistencies | 9 | 9 | 0 | 4 | 0.692 | 1.000 | **0.818** |
| **TOTAL** | **All 5 Rule Families** | **78** | **78** | **0** | **12** | **0.867** | **1.000** | **0.929** |

---

## 3. Decoy Resistance (Precision Safeguards)

Plumbline was tested against 20 deliberate negative decoys across Python, JavaScript, Dockerfile, GitHub Actions, and Go. Each decoy consists of benign code that superficially resembles a vulnerability (such as parameterized SQL, explicit `verify=True`, architectural comments, or safe JSON parsing).

| Decoy ID | Target Subsystem | Pattern Tested | Expected Outcome | Actual Outcome | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DEC001` | `bench/victim/api/db.py` | Parameterized SQLite `?` placeholder | No finding | Clean | ✅ PASS |
| `DEC002` | `bench/victim/api/db.py` | Named parameter query `:uid` | No finding | Clean | ✅ PASS |
| `DEC003` | `bench/victim/api/auth.py` | Salted SHA-256 password hash | No finding | Clean | ✅ PASS |
| `DEC004` | `bench/victim/api/auth.py` | Cryptographic `secrets.token_hex(32)` | No finding | Clean | ✅ PASS |
| `DEC005` | `bench/victim/api/payments.py` | Safe `json.loads` deserialization | No finding | Clean | ✅ PASS |
| `DEC006` | `bench/victim/api/payments.py` | Explicit `verify=True` TLS certificate check | No finding | Clean | ✅ PASS |
| `DEC007` | `bench/victim/api/orders.py` | Route protected by `@require_auth` | No finding | Clean | ✅ PASS |
| `DEC008` | `bench/victim/api/orders.py` | Webhook dispatched to fixed Stripe domain | No finding | Clean | ✅ PASS |
| `DEC009` | `bench/victim/api/utils.py` | Architectural comment explaining rationale | No finding | Clean | ✅ PASS |
| `DEC010` | `bench/victim/frontend/src/app.js` | Safe `JSON.parse` state deserialization | No finding | Clean | ✅ PASS |
| `DEC011` | `bench/victim/tests/test_api.py` | Functional test suite with assertions | No finding | Clean | ✅ PASS |
| `DEC012` | `bench/victim/.github/deploy.yml` | SHA-pinned GitHub Action checkout step | No finding | Clean | ✅ PASS |
| `DEC013` | `bench/victim/Dockerfile` | Production `npm ci --only=production` | No finding | Clean | ✅ PASS |
| `DEC014` | `bench/victim/.cursorrules` | Standard developer coding instruction | No finding | Clean | ✅ PASS |
| `DEC015` | `bench/victim/api/config.py` | Production database connection timeout | No finding | Clean | ✅ PASS |
| `DEC016` | `bench/victim-go/main.go` | Cryptographically secure Go SHA-256 | No finding | Clean | ✅ PASS |
| `DEC017` | `bench/victim-go/main.go` | Structured error logging in Go | No finding | Clean | ✅ PASS |
| `DEC018` | `bench/victim-go/main.go` | Strongly-typed Go constant declarations | No finding | Clean | ✅ PASS |
| `DEC019` | `bench/victim/docs/guide.md` | Valid relative markdown link | No finding | Clean | ✅ PASS |
| `DEC020` | `bench/victim/requirements.txt` | Strictly pinned dependency `flask==3.0.0` | No finding | Clean | ✅ PASS |

---

## 4. Claim Ledger Validation Accuracy

| Category | Documented Assertion | Ground Truth Verdict | Plumbline Verdict | Match |
| :--- | :--- | :--- | :--- | :--- |
| `authentication` | The platform provides JWT authentication for user sessions... | `UNSUPPORTED` | `UNSUPPORTED` | ✅ |
| `encryption` | We enforce strict TLS verification on all external payment requests... | `CONTRADICTED` | `CONTRADICTED` | ✅ |
| `encryption` | Includes AES-256 encryption for data at rest. | `CONTRADICTED` | `CONTRADICTED` | ✅ |
| `caching` | Provides Redis caching for high throughput product catalog searches. | `UNSUPPORTED` | `UNSUPPORTED` | ✅ |
| `rate_limiting` | Employs rate limiting across public API endpoints. | `UNSUPPORTED` | `UNSUPPORTED` | ✅ |
| `docker` | Docker deployment support for containerized cloud deployment. | `CONTRADICTED` | `CONTRADICTED` | ✅ |
| `ci` | Continuous Integration with GitHub Actions workflows. | `CONTRADICTED` | `CONTRADICTED` | ✅ |
| `database` | Robust database connectivity and connection pool management. | `VERIFIED` | `VERIFIED` | ✅ |
| `tests` | Includes automated tests for core API endpoints. | `PARTIAL` | `PARTIAL` | ✅ |
| `logging` | Implements structured logging for production observability. | `VERIFIED` | `VERIFIED` | ✅ |
| `input_validation` | Performs strict input validation on all user request parameters. | `UNSUPPORTED` | `UNSUPPORTED` | ✅ |
| `offline` | Offers full offline mode operations without network connectivity. | `UNSUPPORTED` | `UNSUPPORTED` | ✅ |

