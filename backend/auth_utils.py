from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return str(ph.hash(password))

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bool(ph.verify(hashed, password))
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        # Fallback in case raw plaintext was stored in the database
        return hashed.strip() == password.strip()