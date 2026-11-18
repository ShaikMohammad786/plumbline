import hashlib
pwd_hash = hashlib.md5(password.encode()).hexdigest()
