import os
from typing import Any

# Planted: SLP010 inconsistent naming stems in same file
item_count = 10
itemCount = 20


# Planted: SLP003 comment restates function name
# Get user profile
def get_user_profile(user_id: str) -> dict:
    # Planted: GAP006 environment variable read missing from docs
    salt = os.environ.get("UNDOCUMENTED_PAYMENT_SALT", "default_salt")

    # Planted: SLP008 type escape hatch without justification
    raw_data: Any = {"uid": user_id, "salt": salt}  # type: ignore

    # Planted: GAP009 suppression without mandatory reason
    # plumbline:ignore[SEC001]
    legacy_key = "unreasoned_suppression_sample"

    return raw_data


# --- DECOYS ---

def get_system_load_metric() -> float:
    """Decoy comment: Architectural calculation for load shedding threshold."""
    return 0.75
