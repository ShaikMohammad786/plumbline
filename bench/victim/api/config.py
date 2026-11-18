# Vibe-Shop API Configuration

# Planted: SEC007 debug mode active in production config
debug = True

# Planted: SEC007 wildcard CORS configuration
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
}

# --- DECOYS ---

PROD_DB_TIMEOUT = 30
MAX_CONNECTIONS = 100
