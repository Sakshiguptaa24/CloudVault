# CloudVault 2.0: Quality Assurance & Testing Strategy
**Project:** CloudVault 2.0 – Intelligent Cloud Backup, Security & Disaster Recovery Platform  
**Total Automated Tests:** 51 Tests Across 15 Test Suites  
**Verification Result:** 100% Passed (0 Failures, 0 Regressions)  
**Execution Runtime:** ~9.1 seconds  
**Test Harness:** Pytest 9.2, FastAPI TestClient, AnyIO, In-Memory / Isolated SQLite  

---

## 1. Testing Philosophy & Verification Pyramid

CloudVault 2.0 enforces a multi-tiered testing strategy designed to validate correctness from mathematical primitives up to full end-to-end cloud recovery:

```
                   ┌──────────────────────────────────────┐
                   │    Disaster Recovery & Drills        │
                   │ (Bit-level sandbox SHA verification) │
                   ├──────────────────────────────────────┤
                   │       AI Safety & Token Guards       │
                   │ (Anti-replay nonces, cross-user lock)│
                   ├──────────────────────────────────────┴──────┐
                   │          Security & Crypto Core             │
                   │ (AES-256-GCM, RFC 6238 TOTP, Entropy Math)  │
                   ├─────────────────────────────────────────────┴──────┐
                   │            Multi-Cloud Integration Suites          │
                   │     (GCS, AWS S3, Azure Blob, Air-Gapped Mock)     │
                   ├────────────────────────────────────────────────────┴──────┐
                   │               Core Data Engine & Deduplication            │
                   │     (Streaming SHA-256, Content-Addressed Storage)        │
                   └───────────────────────────────────────────────────────────┘
```

---

## 2. Complete Test Suite Inventory (51 Tests)

### 1. AI Copilot & Safety Protocol (`test_ai_assistant.py`) — 8 Tests
- `test_ai_capabilities`: Validates schema and whitelist of read-only queries vs controlled actions.
- `test_ai_read_only_queries`: Verifies metadata lookups for file protection counts, snapshot history, and storage metrics without state mutation.
- `test_ai_controlled_action_and_replay_protection`: Verifies HMAC-SHA256 signature generation, 5-minute expiration, and strict anti-replay nonce tracking.
- `test_ai_cross_user_token_protection`: Confirms that a confirmation token minted for User A is rejected with HTTP 400 when submitted by User B.
- `test_ai_audit_log_hash_chaining`: Verifies immutable hash chain linkage ($\text{Entry Hash} = \text{SHA-256}(\text{Prev Hash} \parallel \text{Entry Data})$).
- `test_ai_milestone_restore_file_flow`: Complete 9-step end-to-end flow demonstrating restore proposal, signed token, human confirmation, SHA-256 verification, and audit chaining.
- `test_ai_all_ten_example_queries`: Validates clean answers across all 10 user queries without fabricated stats.
- `test_ai_external_llm_fallback_resilience`: Verifies graceful fallback to offline local semantic rules when external LLM is unreachable.

### 2. Cyber Defense & Ransomware Detection (`test_ransomware_detection.py`) — 14 Tests
- `test_shannon_entropy_calculation`: Validates mathematical accuracy of the Shannon entropy engine ($H \in [0.0, 8.0]$).
- `test_high_entropy_compressed_files_not_quarantined`: Confirms that naturally high-entropy compressed files (`.zip`, `.jpg`, `.mp4`) never trigger false-positive quarantine.
- `test_high_entropy_encrypted_files_with_ransomware_extensions`: Verifies ransomware extension detection (`.locked`, `.crypto`) with elevated risk $\ge 80$.
- `test_rapid_bulk_file_modifications_burst`: Tests velocity monitoring on large bursts of modified files.
- `test_suspicious_double_extensions`: Verifies detection of obfuscated double extensions (e.g. `payroll.pdf.locked`).
- `test_large_deletion_bursts`: Tests anomaly detection when sudden large deletions occur.
- `test_combined_anomaly_signals`: Verifies multi-signal correlation (extension + entropy + velocity + deletion).
- `test_false_positive_delta_entropy_handling`: Compares file entropy against historical clean baselines to separate natural edits from encryption spikes.
- `test_alert_generation_and_snapshot_preservation`: Confirms automatic WORM immutability locking of prior clean snapshots on elevated risk.
- `test_quarantine_resolution_and_reversal`: Validates reversible alert resolution and snapshot unquarantine.
- `test_safe_simulation_sandbox_execution`: Verifies isolated sandbox attack simulations for mass encryption and archive scenarios.
- `test_cross_user_security_isolation`: Confirms strict tenant isolation for alerts and dismissal operations.
- `test_ai_security_assistant_queries`: Tests all 6 AI assistant security queries (suspicious activity, flagged backup explanation, affected files, risk score, clean recovery snapshot, next steps).
- `test_authorization_of_sensitive_recovery_actions_under_alert`: Verifies cryptographic token authorization for sensitive remediation actions.

### 3. Disaster Recovery Center (`test_disaster_recovery.py`) — 4 Tests
- `test_shannon_entropy_calculation`: Validates mathematical accuracy of the Shannon entropy engine ($H \in [0.0, 8.0]$).
- `test_high_entropy_alone_does_not_trigger_quarantine`: Confirms that naturally high-entropy compressed files (`.zip`, `.jpg`) never trigger false-positive quarantine.
- `test_simulated_ransomware_detection_and_quarantine`: Simulates multi-signal ransomware attack; confirms risk score $\ge 70$, quarantine alert, and automated WORM snapshot shielding.
- `test_security_router_apis`: Tests alert dismissal, health endpoints, and directory analysis routes.

### 4. Advanced Security Core (`test_security_core.py`)
- `test_aes_gcm_envelope_encryption_roundtrip`: Verifies PBKDF2 KEK derivation, HMAC-SHA256 DEK derivation, and AES-256-GCM encryption/decryption roundtrip.
- `test_aes_gcm_corrupted_ciphertext_fails_auth`: Injects a single corrupted byte; confirms cryptographic verification failure via GCM auth tag.
- `test_totp_rfc6238_generation_and_verification`: Verifies RFC 6238 TOTP engine, secret generation, constant-time verification window, and drift tolerance.
- `test_mfa_enable_and_recovery_codes_flow`: Tests full MFA enrollment, 8 hashed one-time backup codes, and emergency recovery authentication.
- `test_worm_immutable_snapshot_deletion_prevention`: Verifies WORM snapshot immutability; confirms deletion attempts return HTTP 403 Forbidden.

### 5. Multi-Cloud Storage Adapters (`test_cloud_storage_adapters.py`)
- `test_mock_storage_provider_lifecycle`: Tests capabilities, health probes, streaming bytes, and metadata on local air-gapped storage.
- `test_s3_storage_provider_lifecycle`: Tests AWS S3 adapter lifecycle, capabilities, S3 Object Lock, and simulated tiering.
- `test_azure_blob_storage_provider_lifecycle`: Tests Azure Blob Storage adapter lifecycle, immutable blob containers, and hot/cool/archive tiering.
- `test_multi_cloud_inventory_and_endpoints`: Tests `/api/v1/storage/clouds` multi-cloud status and `/api/v1/health` diagnostics.

### 6. Predictive AI Analytics (`test_predictive_analytics.py`)
- `test_analytics_overview`: Validates logical vs physical storage calculations, deduplication multipliers, and cloud cost estimations.
- `test_storage_forecast_baseline_and_growth`: Tests linear growth modeling and days-to-quota projections across 7, 14, and 30-day windows.
- `test_backup_health_score`: Tests multi-dimensional 100-point health score (RPO, reliability, security shield, and deduplication).

### 7. Real-Time Events & Notifications (`test_events.py`)
- `test_events_poll_endpoint`: Tests fallback polling endpoint returning active backup jobs, new ransomware alerts, and completed DR drills.

### 8. Frontend & Progressive Web App (`test_pwa_and_frontend.py`)
- `test_pwa_manifest`: Verifies `manifest.json` structure, app icons, standalone display mode, and PWA metadata.
- `test_service_worker`: Verifies `sw.js` cache-first static strategy and mandatory `/api/` network-bypass security rule.
- `test_offline_page`: Verifies `/offline.html` fallback document.
- `test_frontend_root`: Verifies root document serving.
- `test_health_endpoint`: Tests Core health status and versioning.
- `test_pwa_icons_exist`: Confirms all icon assets exist on disk.

### 9. Core Engine Regression Suites
- `test_auth.py`: User registration, native `bcrypt` salt/hashing, and JWT token issuance.
- `test_dedup_and_backup.py`: Streaming SHA-256 deduplication and 0-byte cloud transfer verification.
- `test_restore_and_integrity.py`: Bit-for-bit SHA-256 integrity verification upon restore and soft-delete trash recovery.
- `test_storage_provider.py`: Mock storage provider file and bytes operations.
- `test_api_integration.py`: End-to-end API backup workflow.
- `test_end_to_end_verification.py`: Full 10-step platform lifecycle test.

---

## 3. How to Run the Verification Suite

Run all tests in one command:
```powershell
python -m pytest backend/tests/ -v
```
Or via the project CLI:
```powershell
python cli.py test
```
