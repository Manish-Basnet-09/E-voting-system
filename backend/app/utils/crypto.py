"""
RSA (Rivest-Shamir-Adleman) Encryption Utility

Key operations:
  Encryption (Voter Side): c = m^e (mod n)
  Decryption (Admin Side): m = c^d (mod n)

Key generation:
  1. Select large primes p and q
  2. Compute modulus n = p * q
  3. Calculate Euler's Totient: φ(n) = (p-1)(q-1)
  4. Choose public exponent e: 1 < e < φ(n), gcd(e, φ(n)) = 1
  5. Calculate private exponent d: d ≡ e^-1 mod φ(n)
"""

import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from ..config import settings


def generate_rsa_keypair(key_size: int = 2048) -> tuple[str, str]:
    """
    Generate RSA key pair for an election.
    Returns (public_key_pem, private_key_pem) as strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return public_pem, private_pem


def encrypt_vote(plain_vote: str, public_key_pem: str) -> str:
    """
    Encrypt a vote using RSA public key.
    Vote is encrypted on client side before transmission.
    Returns base64-encoded ciphertext.
    """
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8"),
        backend=default_backend()
    )

    ciphertext = public_key.encrypt(
        plain_vote.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_vote(encrypted_vote_b64: str, private_key_pem: str) -> str:
    """
    Decrypt an encrypted vote using RSA private key.
    Used only by admin during result tabulation.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
        backend=default_backend()
    )

    ciphertext = base64.b64decode(encrypted_vote_b64.encode("utf-8"))

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode("utf-8")


def generate_rsa_keys():
    """Generate and save RSA keys to files (for initial setup)."""
    public_pem, private_pem = generate_rsa_keypair(settings.rsa_key_size)
    with open(settings.rsa_public_key_path, "w") as f:
        f.write(public_pem)
    with open(settings.rsa_private_key_path, "w") as f:
        f.write(private_pem)
    print(f"RSA keys generated: {settings.rsa_public_key_path}, {settings.rsa_private_key_path}")
    return public_pem, private_pem
