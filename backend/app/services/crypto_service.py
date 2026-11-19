import os
import hmac
import hashlib
import struct
import time
import base64
import secrets
from typing import Tuple, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from backend.app.config import settings

# =====================================================================
# AES-256-GCM ENVELOPE ENCRYPTION
# =====================================================================

def derive_user_kek(user_id: str, salt: str, master_secret: str = None) -> bytes:
    """
    Derive a 256-bit Key Encryption Key (KEK) unique to the user using PBKDF2-HMAC-SHA256.
    Uses per-user salt and application master secret.
    """
    secret = master_secret or settings.SECRET_KEY
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        iterations=100000
    )
    return kdf.derive(f"{user_id}:{secret}".encode("utf-8"))

def derive_object_dek(user_kek: bytes, plaintext_sha256: str) -> bytes:
    """
    Derive a deterministic Data Encryption Key (DEK) for a specific plaintext block.
    This preserves Content-Addressable Storage (CAS) deduplication for the user,
    preventing duplicate cloud storage consumption while ensuring zero cross-user leakage.
    """
    return hmac.new(user_kek, plaintext_sha256.encode("utf-8"), hashlib.sha256).digest()

def encrypt_payload_aes_gcm(plaintext: bytes, key: bytes, nonce: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encrypt payload with AES-256-GCM authenticated encryption.
    Returns: (ciphertext_with_auth_tag, 12_byte_nonce)
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    aesgcm = AESGCM(key)
    nonce = nonce or secrets.token_bytes(12)
    # Encrypt appends the 16-byte authentication tag to the ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce

def decrypt_payload_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt and verify authentication tag of AES-256-GCM payload.
    Raises ValueError if ciphertext or authentication tag is corrupted.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    if len(nonce) != 12:
        raise ValueError("AES-GCM requires a 12-byte nonce.")

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Cryptographic verification failed: ciphertext is corrupted or tampered.") from e

# =====================================================================
# MULTI-FACTOR AUTHENTICATION (TOTP RFC 6238)
# =====================================================================

def generate_totp_secret() -> str:
    """Generate a random 160-bit Base32 TOTP secret."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("utf-8").replace("=", "")

def get_totp_uri(email: str, secret: str, issuer: str = "CloudVault") -> str:
    """Generate standard otpauth:// URI for QR code pairing."""
    return f"otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

def compute_totp_code(secret: str, timestamp: Optional[float] = None, interval: int = 30) -> str:
    """Compute standard 6-digit TOTP code for the given timestamp."""
    t = timestamp if timestamp is not None else time.time()
    counter = int(t // interval)
    msg = struct.pack(">Q", counter)

    # Pad secret if needed for base32 decoding
    padded_secret = secret.upper() + ("=" * (-len(secret) % 8))
    key = base64.b32decode(padded_secret, casefold=True)

    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"

def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code within a +/- window tolerance (to absorb clock drift).
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    clean_code = str(code).strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    now = time.time()
    for offset in range(-window, window + 1):
        test_time = now + (offset * 30)
        expected = compute_totp_code(secret, test_time)
        if hmac.compare_digest(clean_code, expected):
            return True

    return False

def generate_recovery_codes(count: int = 8) -> List[str]:
    """Generate alphanumeric one-time backup recovery codes."""
    codes = []
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        codes.append(f"{part1}-{part2}")
    return codes

def hash_recovery_code(code: str) -> str:
    """Hash a recovery code with SHA-256 for secure storage."""
    clean = code.strip().upper().replace("-", "")
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()

