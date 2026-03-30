import hashlib
import secrets
import hmac
from ..config import settings


def generate_salt(length: int = 32) -> str:
    """Generate a cryptographically secure random salt."""
    return secrets.token_hex(length)


def hash_student_id(student_id: str, salt: str) -> str:
    """
    SHA-256 salted hash of student ID.
    
    Process:
    1. Combine salt + pepper + student_id
    2. Encode to bytes
    3. Apply SHA-256
    4. Return 64-char hexadecimal string
    
    This implements the One-ID-One-Vote enforcement mechanism.
    """
    # Combine student_id with salt and global pepper
    salted_input = f"{salt}{settings.hash_pepper}{student_id}"
    
    # Apply SHA-256 hashing
    hash_digest = hashlib.sha256(salted_input.encode("utf-8")).hexdigest()
    return hash_digest


def verify_student_id(student_id: str, salt: str, stored_hash: str) -> bool:
    """Verify a student ID against its stored hash using constant-time comparison."""
    computed = hash_student_id(student_id, salt)
    return hmac.compare_digest(computed, stored_hash)


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with a generated salt."""
    salt = generate_salt()
    salted = f"{salt}{settings.hash_pepper}{password}"
    pwd_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()
    return f"{salt}:{pwd_hash}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        salt, pwd_hash = stored_hash.split(":", 1)
        salted = f"{salt}{settings.hash_pepper}{plain_password}"
        computed = hashlib.sha256(salted.encode("utf-8")).hexdigest()
        return hmac.compare_digest(computed, pwd_hash)
    except Exception:
        return False


def generate_transaction_hash(voter_id_hash: str, election_id: int, 
                               encrypted_vote: str, timestamp: str) -> str:
    """
    Generate a transaction hash (digital seal) for a cast vote.
    If any part of the vote is altered, this hash will not match.
    """
    data = f"{voter_id_hash}|{election_id}|{encrypted_vote}|{timestamp}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
