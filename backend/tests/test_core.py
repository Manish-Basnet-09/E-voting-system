"""
Test suite for E-Voting System — Patan Multiple Campus
"""
import pytest
from app.utils.hashing import (
    generate_salt, hash_student_id, verify_student_id,
    hash_password, verify_password, generate_transaction_hash
)
from app.utils.crypto import generate_rsa_keypair, encrypt_vote, decrypt_vote
from app.ml.anomaly_detector import VotingAnomalyDetector


# ── Hashing Tests ─────────────────────────────────────────────────────────────

class TestSHA256Hashing:
    def test_generate_salt_uniqueness(self):
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2

    def test_hash_student_id_deterministic(self):
        salt = generate_salt()
        h1 = hash_student_id("79010020", salt)
        h2 = hash_student_id("79010020", salt)
        assert h1 == h2

    def test_hash_student_id_length(self):
        salt = generate_salt()
        h = hash_student_id("79010020", salt)
        assert len(h) == 64  # SHA-256 = 64 hex chars

    def test_verify_student_id_correct(self):
        salt = generate_salt()
        student_id = "79010020"
        stored = hash_student_id(student_id, salt)
        assert verify_student_id(student_id, salt, stored) is True

    def test_verify_student_id_wrong(self):
        salt = generate_salt()
        stored = hash_student_id("79010020", salt)
        assert verify_student_id("99999999", salt, stored) is False

    def test_different_salt_different_hash(self):
        salt1 = generate_salt()
        salt2 = generate_salt()
        h1 = hash_student_id("79010020", salt1)
        h2 = hash_student_id("79010020", salt2)
        assert h1 != h2  # Salt prevents rainbow table attacks

    def test_password_hash_and_verify(self):
        pwd = "SecurePass@123"
        stored = hash_password(pwd)
        assert verify_password(pwd, stored) is True
        assert verify_password("WrongPass", stored) is False

    def test_transaction_hash_changes_if_tampered(self):
        h1 = generate_transaction_hash("abc", 1, "encrypted", "2025-01-01")
        h2 = generate_transaction_hash("abc", 1, "TAMPERED", "2025-01-01")
        assert h1 != h2  # Data integrity check


# ── RSA Encryption Tests ──────────────────────────────────────────────────────

class TestRSAEncryption:
    def test_key_generation(self):
        pub, priv = generate_rsa_keypair(key_size=1024)  # 1024 for test speed
        assert "BEGIN PUBLIC KEY" in pub
        assert "BEGIN PRIVATE KEY" in priv

    def test_encrypt_decrypt_roundtrip(self):
        pub, priv = generate_rsa_keypair(key_size=1024)
        vote = "5"  # Candidate ID
        encrypted = encrypt_vote(vote, pub)
        decrypted = decrypt_vote(encrypted, priv)
        assert decrypted == vote

    def test_encrypted_is_not_plaintext(self):
        pub, priv = generate_rsa_keypair(key_size=1024)
        vote = "3"
        encrypted = encrypt_vote(vote, pub)
        assert vote not in encrypted  # Vote is not visible in ciphertext

    def test_different_encryptions_same_plaintext(self):
        pub, priv = generate_rsa_keypair(key_size=1024)
        e1 = encrypt_vote("2", pub)
        e2 = encrypt_vote("2", pub)
        assert e1 != e2  # OAEP padding produces different ciphertexts


# ── Isolation Forest Tests ────────────────────────────────────────────────────

class TestIsolationForest:
    def test_normal_voter_low_score(self):
        det = VotingAnomalyDetector()
        features = det.extract_features(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            time_since_login=45.0,    # 45 seconds — human-like
            login_hour=10,
            votes_from_ip=1,
            session_duration=120.0,   # 2 minutes
            page_interactions=5,
        )
        _, score = det.is_anomalous(features)
        assert score < 0.7  # Should not be flagged

    def test_bot_voter_high_score(self):
        det = VotingAnomalyDetector()
        features = det.extract_features(
            ip_address="10.0.0.1",
            user_agent="",            # No user agent — suspicious
            time_since_login=0.1,     # 0.1 seconds — bot-like
            login_hour=3,             # 3 AM
            votes_from_ip=50,         # Many votes from same IP
            session_duration=0.05,    # Very short session
            page_interactions=0,
        )
        _, score = det.is_anomalous(features)
        assert score >= 0.5  # Should be flagged

    def test_feature_vector_length(self):
        det = VotingAnomalyDetector()
        features = det.extract_features("1.2.3.4", "UA", 30, 10, 1, 60)
        assert len(features) == 6
