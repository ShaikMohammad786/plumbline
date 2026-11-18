# Test suite for vibe-shop core API

# Planted: GAP003 empty test case with no assertions
def test_payment_stub():
    pass


# --- DECOYS ---

def test_order_total_calculation():
    # Decoy: Proper test with assertions
    subtotal = 100.0
    tax = 20.0
    assert subtotal + tax == 120.0
