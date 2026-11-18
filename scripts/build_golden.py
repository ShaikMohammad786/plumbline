"""Generate golden test fixtures for GAP and SLP rule verification."""

from pathlib import Path

golden_root = Path("tests/golden")
golden_root.mkdir(parents=True, exist_ok=True)

# 1. GAP001
g1 = golden_root / "GAP001"
g1.mkdir(exist_ok=True)
(g1 / "pos_1.py").write_text("# TODO: Implement password hashing\n", encoding="utf-8")
(g1 / "pos_2.js").write_text("// FIXME: Fix token authorization\n", encoding="utf-8")
(g1 / "neg_1.py").write_text("# Verified payment calculation logic\n", encoding="utf-8")
(g1 / "neg_2.js").write_text("// Fully tested route handler\n", encoding="utf-8")

# 2. GAP002
g2 = golden_root / "GAP002"
g2.mkdir(exist_ok=True)
(g2 / "pos_1.py").write_text("def authenticate(user, password):\n    pass\n", encoding="utf-8")
(g2 / "pos_2.py").write_text("def verify_token(token):\n    return False\n", encoding="utf-8")
(g2 / "neg_1.py").write_text("def calculate_sum(a, b):\n    return a + b\n", encoding="utf-8")
(g2 / "neg_2.py").write_text(
    "from abc import abstractmethod\n@abstractmethod\ndef handle():\n    pass\n", encoding="utf-8"
)

# 3. GAP003
g3 = golden_root / "GAP003"
g3.mkdir(exist_ok=True)
(g3 / "pos_1.py").write_text(
    "import pytest\n@pytest.mark.skip\ndef test_feature():\n    pass\n", encoding="utf-8"
)
(g3 / "pos_2.js").write_text("it.skip('should process billing', () => {});\n", encoding="utf-8")
(g3 / "neg_1.py").write_text("def test_feature():\n    assert 1 + 1 == 2\n", encoding="utf-8")
(g3 / "neg_2.js").write_text(
    "test('active', () => { expect(true).toBe(true); });\n", encoding="utf-8"
)

# 4. GAP004
g4 = golden_root / "GAP004"
g4.mkdir(exist_ok=True)
(g4 / "pos_1.py").write_text("def execute_transaction():\n    return 42\n", encoding="utf-8")
(g4 / "pos_2.js").write_text("function processOrder() { return 1; }\n", encoding="utf-8")
(g4 / "neg_1.py").write_text("# Main module\ndef main(): pass\n", encoding="utf-8")
(g4 / "neg_2.py").write_text("# Docs helper\n", encoding="utf-8")

# 5. GAP005
g5 = golden_root / "GAP005"
g5.mkdir(exist_ok=True)
(g5 / "pos_1.py").write_text(
    "def handle_unwired_webhook(request):\n    return {'status': 'ok'}\n", encoding="utf-8"
)
(g5 / "pos_2.py").write_text("def payment_handler(data):\n    return True\n", encoding="utf-8")
(g5 / "neg_1.py").write_text(
    "def calculate_discount(x):\n    return x * 0.9\nval = calculate_discount(100)\n",
    encoding="utf-8",
)
(g5 / "neg_2.py").write_text(
    "def parse_config(cfg):\n    return {}\ncfg = parse_config('test')\n", encoding="utf-8"
)

# 6. GAP006
g6 = golden_root / "GAP006"
g6.mkdir(exist_ok=True)
(g6 / "pos_1.py").write_text(
    "import os\nval = os.environ['UNLISTED_SECRET_KEY_123']\n", encoding="utf-8"
)
(g6 / "pos_2.js").write_text("const k = process.env.MY_UNLISTED_API_KEY;\n", encoding="utf-8")
(g6 / "neg_1.py").write_text("import os\np = os.environ['PATH']\n", encoding="utf-8")
(g6 / "neg_2.py").write_text("import os\nh = os.environ['HOME']\n", encoding="utf-8")

# 7. GAP007
g7 = golden_root / "GAP007"
g7.mkdir(exist_ok=True)
(g7 / "pos_1.md").write_text("[Broken Link](non_existent_file_xyz.md)\n", encoding="utf-8")
(g7 / "pos_2.md").write_text("[Missing Doc](docs/missing_page.md)\n", encoding="utf-8")
(g7 / "neg_1.md").write_text("[Official Site](https://example.com)\n", encoding="utf-8")
(g7 / "neg_2.md").write_text("[Section](#heading)\n", encoding="utf-8")

# 8. GAP008
g8 = golden_root / "GAP008"
g8.mkdir(exist_ok=True)
(g8 / "pos_1.py").write_text("# Repo hygiene\n", encoding="utf-8")
(g8 / "pos_2.py").write_text("# Repo hygiene 2\n", encoding="utf-8")
(g8 / "neg_1.py").write_text("# Repo hygiene neg\n", encoding="utf-8")
(g8 / "neg_2.py").write_text("# Repo hygiene neg 2\n", encoding="utf-8")

# 9. GAP009
g9 = golden_root / "GAP009"
g9.mkdir(exist_ok=True)
(g9 / "pos_1.py").write_text("# plumbline:ignore[SEC001]\ndef bad(): pass\n", encoding="utf-8")
(g9 / "pos_2.js").write_text("// plumbline:ignore[GAP002]\nfunction bad() {}\n", encoding="utf-8")
(g9 / "neg_1.py").write_text(
    "# plumbline:ignore[SEC001] Test credential in mock fixture\ndef good(): pass\n",
    encoding="utf-8",
)
(g9 / "neg_2.js").write_text("// Clean file with standard comments\n", encoding="utf-8")

# 10. SLP001
s1 = golden_root / "SLP001"
s1.mkdir(exist_ok=True)
(s1 / "pos_1.py").write_text("try:\n    risky()\nexcept Exception:\n    pass\n", encoding="utf-8")
(s1 / "pos_2.js").write_text("try { risky(); } catch (e) {}\n", encoding="utf-8")
(s1 / "neg_1.py").write_text(
    "try:\n    risky()\nexcept Exception as e:\n    logger.error(e)\n    raise\n", encoding="utf-8"
)
(s1 / "neg_2.js").write_text("try { risky(); } catch (e) { handleError(e); }\n", encoding="utf-8")

# 11. SLP002
s2 = golden_root / "SLP002"
s2.mkdir(exist_ok=True)
(s2 / "pos_1.py").write_text('API_URL = "https://example.com/api"\n', encoding="utf-8")
(s2 / "pos_2.js").write_text('const placeholderData = "your_api_key_here";\n', encoding="utf-8")
(s2 / "neg_1.py").write_text('API_URL = "https://prod.mycompany.com/api"\n', encoding="utf-8")
(s2 / "neg_2.js").write_text("const timeoutMs = 5000;\n", encoding="utf-8")

# 12. SLP003
s3 = golden_root / "SLP003"
s3.mkdir(exist_ok=True)
(s3 / "pos_1.py").write_text(
    "# Get user by id\ndef get_user_by_id(user_id):\n    return None\n", encoding="utf-8"
)
(s3 / "pos_2.js").write_text(
    "// Calculate order total\nfunction calculateOrderTotal(order) {\n    return 0;\n}\n",
    encoding="utf-8",
)
(s3 / "neg_1.py").write_text(
    "# Queries the cached Redis session for active auth\ndef get_user_by_id(user_id):\n    return None\n",
    encoding="utf-8",
)
(s3 / "neg_2.js").write_text(
    "// Applies tiered regional tax calculations\nfunction calculateOrderTotal(order) { return 0; }\n",
    encoding="utf-8",
)

# 13. SLP004
s4 = golden_root / "SLP004"
s4.mkdir(exist_ok=True)
(s4 / "pos_1.py").write_text(
    "# const old = fetch();\n# const res = old.data;\n# return res.status;\n", encoding="utf-8"
)
(s4 / "pos_2.js").write_text("// let a = 10;\n// let b = 20;\n// return a + b;\n", encoding="utf-8")
(s4 / "neg_1.py").write_text(
    "# This is a normal prose explanation.\n# It describes architecture.\n# Without code syntax.\n",
    encoding="utf-8",
)
(s4 / "neg_2.js").write_text(
    "// Standard explanatory note.\n// Another descriptive line.\n// Clean comments.\n",
    encoding="utf-8",
)

# 14. SLP005
s5 = golden_root / "SLP005"
s5.mkdir(exist_ok=True)
(s5 / "pos_1.py").write_text(
    """
def compute_metrics_a(dataset):
    total = 0
    for item in dataset:
        val = item * 2
        total += val
    return total

def compute_metrics_b(dataset):
    total = 0
    for item in dataset:
        val = item * 2
        total += val
    return total
""",
    encoding="utf-8",
)
(s5 / "pos_2.js").write_text(
    """
function sumItemsA(items) {
    let s = 0;
    for (let x of items) {
        let v = x * 3;
        s += v;
    }
    return s;
}
function sumItemsB(items) {
    let s = 0;
    for (let x of items) {
        let v = x * 3;
        s += v;
    }
    return s;
}
""",
    encoding="utf-8",
)
(s5 / "neg_1.py").write_text("def f1(): return 1\ndef f2(): return 2\n", encoding="utf-8")
(s5 / "neg_2.js").write_text(
    "function a() { return 1; }\nfunction b() { return 2; }\n", encoding="utf-8"
)

# 15. SLP006
s6 = golden_root / "SLP006"
s6.mkdir(exist_ok=True)
(s6 / "pos_1.py").write_text("def forward_value(data):\n    return data\n", encoding="utf-8")
(s6 / "pos_2.py").write_text("def pass_token(token):\n    return token\n", encoding="utf-8")
(s6 / "neg_1.py").write_text("def multiply(data):\n    return data * 2\n", encoding="utf-8")
(s6 / "neg_2.py").write_text("def transform(token):\n    return token.upper()\n", encoding="utf-8")

# 16. SLP007
s7 = golden_root / "SLP007"
s7.mkdir(exist_ok=True)
(s7 / "pos_1.py").write_text('print("Debug trace at line 10")\n', encoding="utf-8")
(s7 / "pos_2.js").write_text('console.log("Raw response:", res);\n', encoding="utf-8")
(s7 / "neg_1.py").write_text('logger.info("User logged in: %s", user_id)\n', encoding="utf-8")
(s7 / "neg_2.js").write_text('logger.warn("Rate limit threshold reached");\n', encoding="utf-8")

# 17. SLP008
s8 = golden_root / "SLP008"
s8.mkdir(exist_ok=True)
(s8 / "pos_1.ts").write_text("const data: any = JSON.parse(raw);\n", encoding="utf-8")
(s8 / "pos_2.ts").write_text("// @ts-ignore\nconst val = obj.nonExistent;\n", encoding="utf-8")
(s8 / "neg_1.ts").write_text("const data: Record<string, string> = {};\n", encoding="utf-8")
(s8 / "neg_2.py").write_text("count: int = 10\n", encoding="utf-8")

# 18. SLP009
s9 = golden_root / "SLP009"
s9.mkdir(exist_ok=True)
long_fn = "def giant_function():\n" + "    x = 1\n" * 85
(s9 / "pos_1.py").write_text(long_fn, encoding="utf-8")
branchy_fn = "def branchy():\n" + "    if True: pass\n" * 18
(s9 / "pos_2.py").write_text(branchy_fn, encoding="utf-8")
(s9 / "neg_1.py").write_text("def small_function():\n    return 42\n", encoding="utf-8")
(s9 / "neg_2.py").write_text(
    "def clean_handler(req):\n    if not req: return None\n    return req.id\n", encoding="utf-8"
)

# 19. SLP010
s10 = golden_root / "SLP010"
s10.mkdir(exist_ok=True)
(s10 / "pos_1.py").write_text("user_account_id = 1\nuserAccountId = 2\n", encoding="utf-8")
(s10 / "pos_2.py").write_text("order_item_price = 10\norderItemPrice = 20\n", encoding="utf-8")
(s10 / "neg_1.py").write_text('user_account_id = 1\nuser_profile_name = "demo"\n', encoding="utf-8")
(s10 / "neg_2.py").write_text(
    "const orderItemPrice = 10;\nconst orderItemTax = 2;\n", encoding="utf-8"
)

print("All 19 golden test directories and fixtures generated!")
