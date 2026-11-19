import os
import hmac
import hashlib
import struct
import time
import base64
import secrets
from typing import Tuple, List, Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from backend.app.config import settings

# =====================================================================
# AES-256-GCM ENVELOPE ENCRYPTION
# =====================================================================

def derive_user_kek(user_id: str, salt: str, key_version: int = 1, master_secret: str = None) -> bytes:
    """
    Derive a 256-bit Key Encryption Key (KEK) unique to the user using PBKDF2-HMAC-SHA256.
    Uses per-user salt and application master secret. Supports key versioning for key rotation.
    """
    secret = master_secret or settings.SECRET_KEY
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        iterations=100000
    )
    if key_version == 1:
        payload = f"{user_id}:{secret}".encode("utf-8")
    else:
        payload = f"{user_id}:{secret}:v{key_version}".encode("utf-8")
    return kdf.derive(payload)

def generate_dek() -> bytes:
    """Generate a cryptographically secure random 256-bit Data Encryption Key."""
    return secrets.token_bytes(32)

def derive_object_dek(user_kek: bytes, plaintext_sha256: str) -> bytes:
    """
    Derive a deterministic Data Encryption Key (DEK) for a specific plaintext block.
    Retained for backward compatibility with existing tests.
    """
    return hmac.new(user_kek, plaintext_sha256.encode("utf-8"), hashlib.sha256).digest()

def encrypt_payload_aes_gcm(
    plaintext: bytes,
    key: bytes,
    nonce: Optional[bytes] = None,
    aad: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt payload with AES-256-GCM authenticated encryption.
    Generates a fresh cryptographically random 12-byte nonce if not provided.
    Returns: (ciphertext_with_auth_tag, 12_byte_nonce)
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    aesgcm = AESGCM(key)
    nonce = nonce or secrets.token_bytes(12)
    # Encrypt appends the 16-byte authentication tag to the ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce

def decrypt_payload_aes_gcm(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    aad: Optional[bytes] = None
) -> bytes:
    """
    Decrypt and verify authentication tag of AES-256-GCM payload.
    Raises ValueError if ciphertext or authentication tag or AAD is corrupted.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    if len(nonce) != 12:
        raise ValueError("AES-GCM requires a 12-byte nonce.")

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise ValueError("Cryptographic verification failed: ciphertext is corrupted or tampered.") from e

def envelope_encrypt_payload(
    plaintext: bytes,
    user_id: str,
    salt: str,
    key_version: int = 1,
    aad_context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Zero-trust AES-256-GCM envelope encryption:
    1. Generates a fresh random 256-bit DEK.
    2. Generates unique random 12-byte nonces for payload and DEK.
    3. Derives user KEK for specified key_version.
    4. Encrypts payload with DEK and binds AAD.
    5. Encrypts DEK with KEK using a separate DEK nonce.
    """
    kek = derive_user_kek(user_id, salt, key_version=key_version)
    dek = generate_dek()
    payload_nonce = secrets.token_bytes(12)
    dek_nonce = secrets.token_bytes(12)

    # 1. Encrypt DEK under KEK
    encrypted_dek, _ = encrypt_payload_aes_gcm(dek, kek, nonce=dek_nonce)

    # 2. Encrypt Payload under DEK
    aad_bytes = aad_context.encode("utf-8") if aad_context else None
    ciphertext, _ = encrypt_payload_aes_gcm(plaintext, dek, nonce=payload_nonce, aad=aad_bytes)

    return {
        "ciphertext": ciphertext,
        "payload_nonce": payload_nonce,
        "encrypted_dek": encrypted_dek,
        "dek_nonce": dek_nonce,
        "key_version": key_version,
        "aad_context": aad_context
    }

def envelope_decrypt_payload(
    ciphertext: bytes,
    encrypted_dek: bytes,
    payload_nonce: bytes,
    dek_nonce: bytes,
    user_id: str,
    salt: str,
    key_version: int = 1,
    aad_context: Optional[str] = None
) -> bytes:
    """
    Decrypt envelope-encrypted payload:
    1. Derives user KEK for specified key_version.
    2. Decrypts DEK using KEK and dek_nonce.
    3. Decrypts payload using DEK and payload_nonce, verifying AAD and GCM tag.
    """
    kek = derive_user_kek(user_id, salt, key_version=key_version)
    dek = decrypt_payload_aes_gcm(encrypted_dek, kek, dek_nonce)

    aad_bytes = aad_context.encode("utf-8") if aad_context else None
    return decrypt_payload_aes_gcm(ciphertext, dek, payload_nonce, aad=aad_bytes)

def rotate_user_kek(user_id: str, db: Any) -> int:
    """
    Rotate the Key Encryption Key (KEK) for a user by incrementing their current_key_version.
    New backups will use the new KEK version.
    Existing backups remain accessible because each StorageObject records its own key_version.
    """
    from backend.app.models import User
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User not found: {user_id}")
    
    current_ver = getattr(user, "current_key_version", 1) or 1
    new_ver = current_ver + 1
    user.current_key_version = new_ver
    db.commit()
    db.refresh(user)
    return new_ver

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

