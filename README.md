# CloudVault 2.0 – AI-Powered Cloud Backup, Security & Disaster Recovery

> **Cloud Computing Capstone & Cloud SaaS Foundation**  
> **Status:** Fully Functional & Tested (38/38 Tests Passing)  
> **Architectural Paradigm:** Multi-Cloud Storage • AI Copilot • Ransomware Shield • Disaster Recovery Center • Envelope Encryption  
> **Compatibility:** Windows 10/11, macOS, Linux • Responsive Mobile/Tablet/Desktop PWA  

---

## 1. Executive Summary

**CloudVault 2.0** transforms standard cloud backups into an **intelligent, autonomous, and self-defending cyber-resilience platform**. Built upon a high-performance Python FastAPI backend, SQLite database, and responsive Progressive Web App frontend, CloudVault 2.0 combines enterprise backup engineering with machine learning and automated disaster recovery.

```
+-----------------------------------------------------------------------------------+
|                                 CLOUDVAULT 2.0                                    |
|    Intelligent Cloud Backup, Cybersecurity & Disaster Recovery Architecture       |
+-----------------------------------------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
+-------v-------+                 +-------v-------+                 +-------v-------+
|  AI COPILOT   |                 | CYBER DEFENSE |                 | DISASTER REC. |
|  ORCHESTRATOR |                 |   & SHIELD    |                 |    CENTER     |
|               |                 |               |                 |               |
| - Natural NLP |                 | - Shannon     |                 | - Calculated  |
| - HMAC-SHA256 |                 |   Entropy H   |                 |   RPO Monitor |
|   Signatures  |                 | - Ransomware  |                 | - Measured    |
| - Anti-Replay |                 |   Signatures  |                 |   RTO Drills  |
| - Immutable   |                 | - WORM Auto-  |                 | - Bit-Level   |
|   Audit Chain |                 |   Shielding   |                 |   Sandbox Run |
+-------+-------+                 +-------+-------+                 +-------+-------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                       SECURITY & MULTI-CLOUD STORAGE CORE                         |
|                                                                                   |
|  * AES-256-GCM Envelope Encryption (User KEK + Deterministic DEK Intra-User Dedup)|
|  * RFC 6238 TOTP Multi-Factor Authentication & Single-Use Recovery Codes          |
|  * Content-Addressed Storage (CAS) Deduplication with Gzip Compression            |
|  * Multi-Cloud Adapters: Google Cloud Storage (GCS) | AWS S3 | Azure Blob | Mock |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Pillars & Major Features

### 🤖 1. AI CloudVault Copilot (Intelligent Assistant)
- **Natural Language Backup Intelligence:** Ask questions like *"How many files are protected?"*, *"Explain my storage savings"*, *"Which files have not been backed up recently?"*, or *"Is my backup system healthy?"*.
- **Cryptographic Human-in-the-Loop Action Protocol:** The AI **never** executes mutating or destructive actions autonomously. Sensitive operations (`TRIGGER_BACKUP`, `RESTORE_FILE`, `LOCK_SNAPSHOT`) generate a single-use, 5-minute cryptographic HMAC-SHA256 authorization token requiring explicit user confirmation.
- **Anti-Replay Protection:** Nonce tracking prevents consumed tokens from ever being replayed.
- **Tamper-Evident Audit Logging:** Every AI proposal and execution is permanently logged to an immutable hash chain where each record incorporates the SHA-256 digest of the preceding record.

### 🛡️ 2. AI-Powered Ransomware & Threat Shield
- **Shannon Entropy Detection Engine:** Computes Shannon entropy ($H \in [0.0, 8.0]$ bits/byte) across file payloads. Files exhibiting $H \ge 7.50$ bits/byte indicate encryption or compression.
- **Multi-Signal Anomaly Scoring (0–100):** Combines known ransomware extension signatures (`.locked`, `.crypto`, `.wnry`, `.crypted`, etc.) with entropy deviations and mass modification velocity.
- **False-Positive Prevention:** Naturally compressed or encrypted media (`.zip`, `.jpg`, `.mp4`, `.pdf`) are shielded from false positives; high entropy alone **never** triggers false quarantine.
- **Automated WORM Snapshot Shielding:** On high-risk detection, existing clean snapshots are automatically locked against deletion to protect recovery points from ransomware tampering.

### 📊 3. Predictive AI Analytics & Storage Intelligence
- **Unified Backup Health Score (0–100):** Weighted multi-dimensional health index evaluating RPO recency (35 pts), job reliability (30 pts), security posture (20 pts), and deduplication efficiency (15 pts).
- **30-Day Storage Growth Forecasting:** Predictive regression models forecast physical storage consumption across 7, 14, and 30-day horizons and calculate days until quota exhaustion.
- **Cloud Cost Estimation:** Live cost calculator modeling monthly spend across Google Cloud Storage tiers (`STANDARD` vs `NEARLINE`) and tracking exact dollar savings achieved through deduplication.
- **Top 10 Storage Heavyweights:** Identifies the largest disk consumers in the vault.

### 🚨 4. Disaster Recovery Center & Synthetic Drills
- **Live RPO & RTO Telemetry:** Computes actual Recovery Point Objective (hours since last verified snapshot) and measured Recovery Time Objective (restoration throughput in MB/s).
- **Sandboxed Synthetic Recovery Drills:** One-click automated recovery drill streams encrypted backup blocks from cloud storage into an isolated temporary directory, decrypts and decompresses payloads, recomputes SHA-256 digests, measures real-world network throughput, and safely wipes the temporary sandbox without touching primary files.
- **Snapshot Verification Attestation:** Marks snapshots as `VERIFIED` or `FAILED` based on bit-level integrity drill outcomes.

### 🔒 5. Advanced Security & Envelope Encryption
- **AES-256-GCM Envelope Encryption:** Protects files at rest using per-user Key Encryption Keys (KEK) and deterministic per-object Data Encryption Keys (DEK) derived via `HMAC-SHA256(KEK, Plaintext_SHA256)`. This guarantees **intra-user deduplication** while preventing cross-user data leakage and dictionary attacks.
- **RFC 6238 TOTP Multi-Factor Authentication:** Built-in authenticator support compatible with Google Authenticator, Microsoft Authenticator, and 1Password, accompanied by 8 hashed one-time recovery codes.
- **WORM Immutability:** Enforces Write-Once-Read-Many snapshot retention (`is_locked`, `lock_until`). Locked snapshots reject `DELETE` operations with HTTP 403 Forbidden until their retention window elapses.

### ☁️ 6. Multi-Cloud Storage Architecture
- **Pluggable Multi-Cloud Adapters:** Unified `StorageProvider` abstraction supporting:
  - **Google Cloud Storage (GCS):** Official `google-cloud-storage` SDK integration with bucket health probes and metadata extraction.
  - **Amazon Web Services (AWS S3):** S3 Object Lock and Glacier tiering support.
  - **Microsoft Azure Blob Storage:** Immutable blob container support.
  - **Local Air-Gapped Mock Storage:** Safe offline filesystem emulation with \$0.00 cloud cost for local grading and offline environments.

### 🕒 7. Visual Version Timeline Scrubber & Real-Time SSE
- **Visual File Timeline:** Select any protected file to scrub through its complete historical lineage across snapshots, inspect cryptographic fingerprints, and trigger 1-click version rollbacks.
- **Server-Sent Events (SSE):** Real-time event streaming (`/api/v1/events/stream`) broadcasting backup progress, ransomware alarms, and DR drill results with heartbeat keep-alive.

---

## 3. Quick Start Guide (Windows)

### Step 1: Open PowerShell in Project Directory
```powershell
cd c:\Users\saksh\Desktop\CloudVault
```

### Step 2: Activate Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 3: Run the CloudVault 2.0 Server
```powershell
python cli.py serve
```
Output:
```
=======================================================
  ☁️  CloudVault – Cloud Backup & Recovery System
=======================================================
  💻 Laptop (Localhost):  http://localhost:8000
  📱 Multiple Devices:    http://192.168.1.x:8000 (Same Wi-Fi)
  📖 API Docs (Swagger):  http://localhost:8000/docs
  🔒 Storage Mode:        MOCK
=======================================================
```

Access the application:
- **Web Console:** [http://localhost:8000](http://localhost:8000)
- **Interactive API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 4. CloudVault 2.0 CLI Reference

CloudVault includes a unified command-line interface for administration, testing, and automated scripts:

```powershell
# 1. Start Web Dashboard and API Server
python cli.py serve --port 8000

# 2. Run Full Automated Test Suite (38 tests)
python cli.py test

# 3. Check Unified Health Score & Storage Analytics
python cli.py health

# 4. Scan a Directory for Ransomware Signatures & High Entropy
python cli.py security-scan C:\Path\To\Folder

# 5. Run a Sandboxed Synthetic Disaster Recovery Drill
python cli.py dr

# 6. Execute an On-Demand Folder Backup
python cli.py backup C:\Path\To\Folder --name "Academic Capstone Backup"
```

---

## 5. Automated Verification & Test Results

CloudVault 2.0 features **38 automated unit and integration tests** covering all subsystems:

```powershell
python -m pytest backend/tests/ -v
```

### Verified Test Matrix:
| Test Suite | Tests | Status | Scope Tested |
| :--- | :---: | :---: | :--- |
| `test_ai_assistant.py` | 5 | **PASSED** | Read-only queries, token minting, anti-replay, hash-chain audit logging |
| `test_disaster_recovery.py` | 4 | **PASSED** | RPO/RTO calculation, synthetic drill sandbox, corruption detection, history |
| `test_security_core.py` | 5 | **PASSED** | AES-256-GCM envelope roundtrip, corrupted ciphertext rejection, TOTP MFA, WORM lock |
| `test_ransomware_detection.py` | 4 | **PASSED** | Shannon entropy math, false-positive protection, alert quarantine, auto-lock |
| `test_cloud_storage_adapters.py` | 4 | **PASSED** | Mock, AWS S3 adapter, Azure Blob adapter, multi-cloud inventory |
| `test_predictive_analytics.py` | 3 | **PASSED** | Storage overview, growth forecast regression, 4-factor health score |
| `test_pwa_and_frontend.py` | 6 | **PASSED** | Web app manifest, service worker security cache bypass, offline page, icons |
| `test_events.py` | 1 | **PASSED** | Real-time event notifications & fallback polling |
| `test_auth.py` | 1 | **PASSED** | Registration, bcrypt hashing, JWT issuance, duplicate checks |
| `test_dedup_and_backup.py` | 1 | **PASSED** | CAS deduplication, 0-byte cloud transfer verification |
| `test_restore_and_integrity.py` | 1 | **PASSED** | Bit-level SHA-256 restore verification, soft-delete trash recovery |
| `test_end_to_end_verification.py`| 1 | **PASSED** | Full 10-step complete platform lifecycle |
| `test_storage_provider.py` | 1 | **PASSED** | Core storage provider upload/download/exists interface |
| `test_api_integration.py` | 1 | **PASSED** | REST API backup flow |
| **TOTAL** | **38** | **100% PASSED** | **Execution Duration: ~11.5 seconds** |

---

## 6. University Viva & Live Demonstration Script (7 Minutes)

Follow this structured demonstration script during your academic presentation:

### Phase 1: Authentication, Multi-Cloud Architecture & PWA (1 min)
1. Open `http://localhost:8000` and point out the responsive layout and PWA install prompt.
2. Log in and highlight the storage provider badge: explain how CloudVault abstracts storage to operate offline with \$0.00 cloud costs while being multi-cloud ready for GCS, AWS S3, and Azure.

### Phase 2: Deduplication & Snapshot Creation (1.5 min)
1. In the **"Backup & Protect"** tab, upload a sample file. Show the storage utilization update.
2. Upload the **exact same file** again: point out the instant 0-byte deduplication bypass notice.
3. Create a backup plan pointing to a local directory and click **"Execute Backup Now"**. Show the newly created snapshot in the **"Snapshots"** tab.

### Phase 3: AI CloudVault Copilot with Cryptographic Authorization (1.5 min)
1. Click the floating **"🤖 AI Copilot"** button in the bottom right corner.
2. Click the prompt pill: *"How many files are currently protected?"* and show the instant response.
3. Click the prompt pill: *"Is my backup system healthy?"* to review the AI's diagnostic breakdown.
4. Issue an action prompt: *"Run an on-demand backup now."*
5. Highlight the **Action Authorization Card**: Explain the HMAC-SHA256 single-use token protocol. Click **"✓ Confirm Execution"** to demonstrate human-in-the-loop authorization.
6. Open the **"Security & Ransomware"** tab: show the newly recorded entry in the **Tamper-Evident SHA-256 Audit Log** with its linked hash chain.

### Phase 4: Ransomware Shield & WORM Immutability (1.5 min)
1. Show the **Ransomware Shield** status card: explain Shannon entropy calculation ($H \ge 7.5$) and signature detection.
2. In the terminal, run `python cli.py security-scan backend/app` to demonstrate the live entropy analyzer scanning 70 files with $H = 4.77$ bits/byte.
3. In the Web UI, lock a snapshot under WORM retention. Demonstrate that deleting the locked snapshot returns an HTTP 403 Forbidden error.

### Phase 5: Disaster Recovery Drill & Version Timeline (1.5 min)
1. Switch to the **"🚨 Disaster Recovery"** tab:
   - Point out the calculated **RPO** (e.g. 0.2h) and measured **RTO** (e.g. 1.2 min).
   - Click **"🚀 Run Synthetic Recovery Drill"**: show the live execution streaming blocks, verifying bit-level SHA-256 hashes, and displaying throughput (MB/s).
   - Show the newly appended drill entry in the audit history table.
2. Switch to the **"🕒 Version Timeline"** tab:
   - Select a modified file. Scrub through the timeline showing previous revisions, timestamps, file sizes, and cryptographic SHA-256 digests.
   - Click **"↺ Restore This Version"** to complete the end-to-end loop.

---

## 7. Connecting Production Google Cloud Storage

When ready to connect to a live Google Cloud Storage bucket:

1. Create a bucket in your GCP console:
   ```bash
   gcloud storage buckets create gs://my-cloudvault-bucket --location=us-central1
   ```
2. Place your GCP Service Account JSON key inside the project directory (e.g., `config/gcp-key.json`).
3. Update `.env`:
   ```ini
   STORAGE_PROVIDER=gcs
   GCS_BUCKET_NAME=my-cloudvault-bucket
   GCS_PROJECT_ID=my-gcp-project-id
   GOOGLE_APPLICATION_CREDENTIALS=config/gcp-key.json
   GCS_REGION=us-central1
   ```
4. Restart CloudVault (`python cli.py serve`). The UI badge updates immediately to **"Google Cloud Storage (gs://my-cloudvault-bucket)"**.

---

## 8. Technology Stack Summary

- **Backend:** Python 3.11, FastAPI, Uvicorn, SQLAlchemy ORM, Pydantic v2.
- **Cryptography:** AES-256-GCM (`cryptography`), PBKDF2-HMAC-SHA256 (`hashlib`), native `bcrypt`, RFC 6238 TOTP engine.
- **Database:** SQLite 3 (WAL mode enabled, zero external dependencies).
- **Storage Providers:** Google Cloud Storage SDK (`google-cloud-storage`), AWS S3 adapter, Azure Blob adapter, Air-gapped Mock Provider.
- **Frontend:** Progressive Web App (PWA), HTML5, Vanilla JavaScript (ES6+), Modern Dark-Mode CSS3, Server-Sent Events (SSE).
- **Testing:** Pytest, FastApi TestClient, AnyIO.
