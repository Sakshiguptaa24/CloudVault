# CloudVault 2.0 – Security Architecture & Threat Model

## 1. Executive Summary

CloudVault 2.0 is architected according to **Zero-Trust principles**. It ensures data confidentiality, integrity, availability, and non-repudiation across multi-tenant cloud storage environments.

---

## 2. Multi-Tenant Isolation & Concurrency Safety

CloudVault 2.0 enforces strict tenant isolation at both the web interface layer and the database/storage layer:

1. **State Isolation in Streamlit**:
   - Streamlit scripts rerun per interaction. CloudVault stores zero state in global Python variables.
   - All authentication tokens and user credentials reside strictly inside `st.session_state["access_token"]` and `st.session_state["user"]`.
   - Each browser session, device, or tab maintains its own independent memory space. Concurrent users on different devices cannot inspect, access, or modify each other's session state.

2. **Row-Level Tenant Authorization in Backend**:
   - Every API request passes an authenticated Bearer JWT token in the `Authorization` header.
   - The FastAPI dependency `get_current_user` extracts and cryptographically verifies the subject claim `sub` (User ID).
   - Every database query strictly filters by `user_id == current_user.id`. A user cannot read, query, update, restore, or delete any snapshot, file, plan, alert, or audit log belonging to another user.

---

## 3. Cryptographic Core & Zero-Trust Envelope Encryption

1. **Data Encryption Standard**:
   - Payload data is encrypted using **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and cryptographic authentication against ciphertext tampering.
   - Every storage object receives an authenticated 128-bit authentication tag and a 96-bit unique IV/nonce.

2. **Key Hierarchy (Envelope Encryption)**:
   - **Data Encryption Key (DEK)**: A random 256-bit symmetric key generated per storage object.
   - **Key Encryption Key (KEK)**: Derived per user using **PBKDF2-HMAC-SHA256** with 100,000 iterations and a unique user salt.
   - The KEK encrypts the DEK. The encrypted DEK is stored alongside object metadata. Raw plaintext keys are never stored on disk or logged.

3. **Key Rotation**:
   - Users can rotate their master KEK at any time via the Security Center or API (`/api/v1/security/crypto/rotate-key`).
   - KEK rotation increments `user.current_key_version`. Existing backups remain readable via their per-object key version references.

---

## 4. Multi-Factor Authentication (MFA) & Lockout Controls

1. **RFC 6238 Time-Based One-Time Password (TOTP)**:
   - Standard 6-digit TOTP codes compatible with Google Authenticator, Microsoft Authenticator, Authy, and 1Password.
   - Secrets are generated using cryptographically secure random bytes (base32-encoded).

2. **Emergency Recovery Codes**:
   - When MFA is enabled, 10 cryptographically secure 8-character recovery codes are generated.
   - Only SHA-256 hashes of recovery codes are stored in the database. When used, the code is immediately marked as consumed and cannot be reused.

3. **Brute-Force & Lockout Controls**:
   - Accounts are automatically locked for 15 minutes after 5 consecutive failed MFA attempts.
   - Lockout events trigger `CRITICAL` audit log entries.

---

## 5. Tamper-Evident Cryptographic Audit Ledger

1. **Hash-Chained Audit Logs**:
   - Every security event (login, registration, failure, MFA challenge, key rotation, backup execution, restore operation, alert resolution) is recorded in `audit_logs`.
   - Each entry includes `prev_hash` and `current_hash`:
     $$\text{current\_hash} = \text{SHA256}(\text{prev\_hash} + \text{user\_id} + \text{event\_type} + \text{action} + \text{details} + \text{timestamp})$$
   - Forms an immutable cryptographic ledger from genesis to head.

2. **Integrity Verification**:
   - Users and evaluators can verify the audit ledger at any time via `/api/v1/security/audit-logs/verify` or via the Security Center UI.
   - Any modified, deleted, or inserted historical record breaks the cryptographic chain and triggers an immediate tampering alert.

---

## 6. Ransomware Anomaly Detection & WORM Retention

1. **Heuristic & Entropy Detection**:
   - **Shannon Entropy**: Evaluates byte distribution ($H(X) = -\sum p_i \log_2 p_i$). Entropy above 7.50 flags suspicious high-entropy encryption activity.
   - **Known Extension Matching**: Flags ransomware extensions (`.locked`, `.crypto`, `.enc`, etc.).
   - **Burst Modification Detection**: Flags rapid modifications exceeding threshold (20 files/sec).

2. **Reversible Quarantine**:
   - Detected threats place affected snapshots in quarantined state to prevent accidental restoration of infected payloads.
   - Users can review threat details and reversibly unquarantine snapshots once confirmed safe.

3. **WORM (Write Once, Read Many) Snapshot Protection**:
   - Snapshots carry immutable retention locks (`worm_locked_until`).
   - Deletion or overwrite is strictly forbidden until the retention window expires.
