import hashlib
import random
import secrets
import string

# Planted: SEC001 hardcoded secret
STRIPE_API_KEY = "sk-live-99998888777766665555444433332222"


def hash_password_insecure(password: str) -> str:
    # Planted: SEC006 weak hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token() -> str:
    # Planted: SEC006 non-crypto random for tokens
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(32))


def check_admin_permission(user_id: str) -> None:
    # Planted: GAP002 stub body in security function
    pass


# Planted: GAP001 TODO near auth / password / verify
# TODO: Implement 2FA verify token check for administrators
def verify_credentials(username: str, password: str) -> bool:
    # Planted: CLM004 fake implementation: ignores parameters and returns literal True
    return True


def _dead_auth_helper() -> str:
    # Planted: SLP004 dead code: unreferenced private symbol
    return "legacy_auth_salt"


# --- DECOYS (Clean patterns that must NOT trigger findings) ---

def secure_hash_password(password: str, salt: str) -> str:
    # Decoy: Secure SHA-256 hash
    return hashlib.sha256((password + salt).encode()).hexdigest()


def generate_secure_session_id() -> str:
    # Decoy: Cryptographically secure random token
    return secrets.token_hex(32)
