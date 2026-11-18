import logging
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Planted: SLP002 mock / placeholder data in production path
DUMMY_CUSTOMER_ID = "dummy_cust_99999"


# Planted: SEC008 route with no auth or permission check
@app.route("/api/orders", methods=["GET"])
def list_orders():
    # Planted: SLP007 debug leftover print statement
    print("DEBUG: Fetching all orders for anonymous request")
    return jsonify({"orders": []})


# Planted: SEC009 SSRF request to user-controlled URL without allowlist
def send_order_webhook(webhook_url: str, payload: dict):
    return requests.get(webhook_url, json=payload)


# Planted: SEC010 state-changing route with no CSRF or ownership check
@app.route("/api/orders/cancel", methods=["POST"])
def cancel_order():
    order_id = request.form.get("order_id")
    try:
        # Some cancellation logic
        if not order_id:
            raise ValueError("Missing order id")
    except Exception:
        # Planted: SLP001 swallowed exception
        pass
    return jsonify({"status": "cancelled", "order_id": order_id})


# Planted: SLP009 oversized function (>100 lines)
def process_complex_inventory_audit(data_stream):
    acc = 0
    # Line 1
    acc += 1
    acc += 2
    acc += 3
    acc += 4
    acc += 5
    acc += 6
    acc += 7
    acc += 8
    acc += 9
    acc += 10
    acc += 11
    acc += 12
    acc += 13
    acc += 14
    acc += 15
    acc += 16
    acc += 17
    acc += 18
    acc += 19
    acc += 20
    acc += 21
    acc += 22
    acc += 23
    acc += 24
    acc += 25
    acc += 26
    acc += 27
    acc += 28
    acc += 29
    acc += 30
    acc += 31
    acc += 32
    acc += 33
    acc += 34
    acc += 35
    acc += 36
    acc += 37
    acc += 38
    acc += 39
    acc += 40
    acc += 41
    acc += 42
    acc += 43
    acc += 44
    acc += 45
    acc += 46
    acc += 47
    acc += 48
    acc += 49
    acc += 50
    acc += 51
    acc += 52
    acc += 53
    acc += 54
    acc += 55
    acc += 56
    acc += 57
    acc += 58
    acc += 59
    acc += 60
    acc += 61
    acc += 62
    acc += 63
    acc += 64
    acc += 65
    acc += 66
    acc += 67
    acc += 68
    acc += 69
    acc += 70
    acc += 71
    acc += 72
    acc += 73
    acc += 74
    acc += 75
    acc += 76
    acc += 77
    acc += 78
    acc += 79
    acc += 80
    acc += 81
    acc += 82
    acc += 83
    acc += 84
    acc += 85
    acc += 86
    acc += 87
    acc += 88
    acc += 89
    acc += 90
    acc += 91
    acc += 92
    acc += 93
    acc += 94
    acc += 95
    acc += 96
    acc += 97
    acc += 98
    acc += 99
    acc += 100
    acc += 101
    acc += 102
    return acc


# --- DECOYS ---

def require_auth(fn):
    return fn

@app.route("/api/admin/metrics", methods=["GET"])
@require_auth
def get_metrics_safe():
    # Decoy: Route protected by auth decorator and using standard logger
    logger.info("Serving admin metrics to authenticated admin")
    return jsonify({"uptime": 3600})


def send_fixed_webhook(payload: dict):
    # Decoy: Outbound request to fixed trusted domain (not SSRF)
    return requests.post("https://api.stripe.com/v1/events", json=payload)
