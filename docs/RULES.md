# Plumbline Detection Rules Catalog

This document is automatically generated from registered detector specifications.

| Rule ID | Family | Title | Severity | Confidence | Heuristic |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GAP001` | GAP | Unresolved TODO, FIXME, HACK, or XXX | medium | high | No |
| `GAP002` | GAP | Unimplemented stub function or method | medium | high | No |
| `GAP003` | GAP | Skipped, empty, or unasserted test | medium | high | No |
| `GAP004` | GAP | Untested production module | low | medium | Yes (H) |
| `GAP005` | GAP | Unregistered handler or unreferenced export | medium | medium | Yes (H) |
| `GAP006` | GAP | Undocumented environment variable | low | high | No |
| `GAP007` | GAP | Broken relative documentation link | low | high | No |
| `GAP008` | GAP | Missing repository baseline hygiene | low | high | No |
| `GAP009` | GAP | Suppression without mandatory reason | low | high | No |
| `SLP001` | SLP | Swallowed exception or empty catch block | medium | high | No |
| `SLP002` | SLP | Mock or placeholder data in production path | high | high | No |
| `SLP003` | SLP | Tautological comment restating code name | low | medium | No |
| `SLP004` | SLP | Unreferenced dead code or commented-out code block | low | medium | No |
| `SLP005` | SLP | Near-duplicate functions | low | high | No |
| `SLP006` | SLP | Redundant passthrough wrapper | low | high | No |
| `SLP007` | SLP | Debug leftover in production code | low | high | No |
| `SLP008` | SLP | Type escape hatch without reason | low | high | No |
| `SLP009` | SLP | Oversized or cyclomatically complex function | low | medium | No |
| `SLP010` | SLP | Conflicting identifier naming stems | low | medium | No |

---

## Rule Specifications

### `GAP001`: Unresolved TODO, FIXME, HACK, or XXX

- **Family**: GAP
- **Severity**: medium
- **Confidence**: high
- **Heuristic**: No
- **Tags**: cwe-546, technical-debt
- **Fix Hint**: Resolve the unfinished work or document the tracking issue.

#### Bad Example
```
// TODO: implement rate limiting
```

#### Good Example
```
// Rate limiting implemented via Redis token bucket
```

---

### `GAP002`: Unimplemented stub function or method

- **Family**: GAP
- **Severity**: medium
- **Confidence**: high
- **Heuristic**: No
- **Tags**: cwe-546
- **Fix Hint**: Provide a complete implementation instead of a dummy stub.

#### Bad Example
```
def authenticate(user, password):
    pass
```

#### Good Example
```
def authenticate(user, password):
    return verify_hash(password, user.pwd_hash)
```

---

### `GAP003`: Skipped, empty, or unasserted test

- **Family**: GAP
- **Severity**: medium
- **Confidence**: high
- **Heuristic**: No
- **Tags**: quality, tests
- **Fix Hint**: Un-skip the test or add verifiable assertions.

#### Bad Example
```
@pytest.mark.skip
def test_payments(): pass
```

#### Good Example
```
def test_payments():
    assert charge() == 200
```

---

### `GAP004`: Untested production module

- **Family**: GAP
- **Severity**: low
- **Confidence**: medium
- **Heuristic**: Yes
- **Tags**: tests, coverage
- **Fix Hint**: Add automated test suite covering this module.

#### Bad Example
```
# File: src/payments.py with no tests/test_payments.py
```

#### Good Example
```
# File: src/payments.py with tests/test_payments.py
```

---

### `GAP005`: Unregistered handler or unreferenced export

- **Family**: GAP
- **Severity**: medium
- **Confidence**: medium
- **Heuristic**: Yes
- **Tags**: dead-code, wiring
- **Fix Hint**: Mount handler to an application route or remove unreferenced code.

#### Bad Example
```
def handle_payment_webhook(request): ... # Never mounted on any route
```

#### Good Example
```
app.post('/webhook', handle_payment_webhook)
```

---

### `GAP006`: Undocumented environment variable

- **Family**: GAP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: documentation, configuration
- **Fix Hint**: Document this environment variable in .env.example and README.md.

#### Bad Example
```
api_key = os.environ['STRIPE_KEY'] # Missing from README and .env.example
```

#### Good Example
```
# Documented in .env.example: STRIPE_KEY=your_key_here
```

---

### `GAP007`: Broken relative documentation link

- **Family**: GAP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: documentation, links
- **Fix Hint**: Fix the relative link destination or create the missing file.

#### Bad Example
```
[Architecture](docs/arch.md) # file does not exist
```

#### Good Example
```
[Architecture](docs/ARCHITECTURE.md)
```

---

### `GAP008`: Missing repository baseline hygiene

- **Family**: GAP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: hygiene, repository
- **Fix Hint**: Add installation instructions to README, a LICENSE, and CI configuration.

#### Bad Example
```
# Empty repo without LICENSE, CI, or installation docs
```

#### Good Example
```
# Repository with README install steps, LICENSE, and .github/workflows/ci.yml
```

---

### `GAP009`: Suppression without mandatory reason

- **Family**: GAP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: hygiene
- **Fix Hint**: Provide a mandatory reason justifying why this rule is suppressed.

#### Bad Example
```
// plumbline:ignore[SEC001]
```

#### Good Example
```
// plumbline:ignore[SEC001] Test credential in mock fixture
```

---

### `SLP001`: Swallowed exception or empty catch block

- **Family**: SLP
- **Severity**: medium
- **Confidence**: high
- **Heuristic**: No
- **Tags**: cwe-390, reliability
- **Fix Hint**: Log the exception or re-raise instead of silently suppressing errors.

#### Bad Example
```
try:
    do_work()
except Exception:
    pass
```

#### Good Example
```
try:
    do_work()
except Exception as e:
    logger.error('Failed work: %s', e)
    raise
```

---

### `SLP002`: Mock or placeholder data in production path

- **Family**: SLP
- **Severity**: high
- **Confidence**: high
- **Heuristic**: No
- **Tags**: cwe-1188, ai-slop
- **Fix Hint**: Replace mock/placeholder value with dynamic data or environment configuration.

#### Bad Example
```
USER_API_KEY = "changeme_your_api_key_here"
```

#### Good Example
```
USER_API_KEY = os.environ['USER_API_KEY']
```

---

### `SLP003`: Tautological comment restating code name

- **Family**: SLP
- **Severity**: low
- **Confidence**: medium
- **Heuristic**: No
- **Tags**: ai-slop, clean-code
- **Fix Hint**: Provide meaningful intent or context in the comment, or remove redundant explanation.

#### Bad Example
```
# Get user by id
def get_user_by_id(user_id): pass
```

#### Good Example
```
# Retrieves verified user record from database cache
def get_user_by_id(user_id): ...
```

---

### `SLP004`: Unreferenced dead code or commented-out code block

- **Family**: SLP
- **Severity**: low
- **Confidence**: medium
- **Heuristic**: No
- **Tags**: dead-code, clean-code
- **Fix Hint**: Delete commented-out code blocks; use Git version control for history.

#### Bad Example
```
// const oldData = fetchLegacy();
// formatOld(oldData);
```

#### Good Example
```
# Clean code without blocks of commented-out logic
```

---

### `SLP005`: Near-duplicate functions

- **Family**: SLP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: duplication, dry
- **Fix Hint**: Refactor duplicate logic into a shared helper function.

#### Bad Example
```
def calculate_a(x): ...
def calculate_b(x): ... # 90% identical token sequence
```

#### Good Example
```
def calculate(x, mode): # Consolidated logic
```

---

### `SLP006`: Redundant passthrough wrapper

- **Family**: SLP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: clean-code, refactoring
- **Fix Hint**: Implement actual logic or call the underlying function directly.

#### Bad Example
```
def save_data(data):
    return data
```

#### Good Example
```
def save_data(data):
    database.write(data)
    return data
```

---

### `SLP007`: Debug leftover in production code

- **Family**: SLP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: clean-code, hygiene
- **Fix Hint**: Remove debug statements or replace with structured application logging.

#### Bad Example
```
console.log('Got user:', user);
```

#### Good Example
```
logger.info('Retrieved user %s', user.id)
```

---

### `SLP008`: Type escape hatch without reason

- **Family**: SLP
- **Severity**: low
- **Confidence**: high
- **Heuristic**: No
- **Tags**: typescript, typing
- **Fix Hint**: Use specific types or declare branded interfaces instead of any.

#### Bad Example
```
const user: any = data;
```

#### Good Example
```
const user: UserProfile = validateUser(data);
```

---

### `SLP009`: Oversized or cyclomatically complex function

- **Family**: SLP
- **Severity**: low
- **Confidence**: medium
- **Heuristic**: No
- **Tags**: complexity, maintainability
- **Fix Hint**: Break down large function into smaller, single-purpose functions.

#### Bad Example
```
def monster_function(): # >80 lines or >15 branches
```

#### Good Example
```
def process(): # Decomposed into small, testable units
```

---

### `SLP010`: Conflicting identifier naming stems

- **Family**: SLP
- **Severity**: low
- **Confidence**: medium
- **Heuristic**: No
- **Tags**: naming, consistency
- **Fix Hint**: Adopt consistent naming conventions (snake_case vs camelCase) across identifiers.

#### Bad Example
```
user_account_id = 1
userAccountId = 2
```

#### Good Example
```
user_account_id = 1 # Consistent snake_case throughout file
```

---
