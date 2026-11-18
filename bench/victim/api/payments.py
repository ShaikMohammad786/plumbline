import json
import pickle
import requests
# Planted: DEP007 cross-ecosystem confusion (npm package imported in Python)
import axios

class GatewayClient:
    def charge(self, charge_id: str):
        return {"status": "ok", "id": charge_id}

api_client = GatewayClient()


# Planted: GAP005 handler never registered or called
def handle_orphan_dispute(event_data: dict) -> None:
    pass


def execute_custom_formula(payment_code: str):
    # Planted: SEC002 dynamic code execution
    return eval(payment_code)


def deserialize_payment_payload(payload: bytes):
    # Planted: SEC004 unsafe deserialization
    return pickle.loads(payload)


def submit_charge_remote(data: dict):
    # Planted: SEC005 TLS verification disabled (also contradicts Claim 2)
    url = "https://payment-gateway.internal/v1/charge"
    return requests.post(url, json=data, verify=False)


def process_charge(charge_id: str):
    # Planted: SLP006 passthrough wrapper
    return api_client.charge(charge_id)


# Planted: SLP005 near-duplicate functions (similarity >= 0.85)
def calculate_vat_tax_zone_a(base_price: float, quantity: int) -> float:
    vat_rate = 0.20
    subtotal = base_price * quantity
    tax_amount = subtotal * vat_rate
    total_cost = subtotal + tax_amount
    return total_cost


def calculate_vat_tax_zone_b(base_price: float, quantity: int) -> float:
    vat_rate = 0.21
    subtotal = base_price * quantity
    tax_amount = subtotal * vat_rate
    total_cost = subtotal + tax_amount
    return total_cost


# --- DECOYS ---

def safe_deserialize_json(payload: str):
    # Decoy: Safe JSON parsing (not pickle/yaml)
    return json.loads(payload)


def safe_submit_charge(data: dict):
    # Decoy: Explicit TLS verification enabled
    return requests.post("https://api.stripe.com/v1/charges", json=data, verify=True)
