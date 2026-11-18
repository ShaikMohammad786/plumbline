import hashlib
pwd_hash = hashlib.sha256(password.encode()).hexdigest()
