# CloudVault: Requirements Specification Document
**Project:** CloudVault – Cloud-Based Backup and Recovery System  
**Course:** Cloud Computing Technology (4–6 Week University Project)  
**Primary Cloud Platform:** Google Cloud Storage (with Local Mock Storage for Dev/Test)  
**Author / Architect:** Senior Software Architect & Technical PM  
**Status:** Approved Baseline  
**Date:** November 2026  

---

## 1. Executive Summary & Project Objectives

CloudVault is a practical, cloud-based backup and disaster recovery system designed for a university Cloud Computing Technology curriculum. The system demonstrates core cloud computing principles—cloud object storage abstraction, file-level deduplication, automated scheduling, point-in-time snapshot recovery, and deleted-file restoration—while remaining simple, robust, and achievable within a 4–6 week timeline.

### Core Objectives:
1. **Automated Protection:** Provide reliable scheduled and on-demand file backups without manual intervention.
2. **Storage & Bandwidth Optimization:** Implement file-level deduplication (SHA-256 content hashing) and compression to minimize storage footprints.
3. **Point-in-Time Recovery & Versioning:** Allow users to explore historical snapshots and restore exact file versions or accidentally deleted files.
4. **Cloud Storage Integration:** Integrate Google Cloud Storage (GCS) using clean abstraction, with server-side encryption at rest and secure transit.
5. **Zero-Cost Development:** Support a full-featured local mock storage environment so that 100% of development, testing, and grading can run locally without incurring cloud costs or requiring active cloud credentials.

---

## 2. User Personas & Stakeholders

| Persona | Description | Key Workflows |
|---|---|---|
| **End User (Student / Workstation User)** | Installs the CloudVault agent; selects directories to back up; sets schedules; browses snapshot history; restores files or undeletes lost data. | Logs in, defines backup folders, triggers manual backup, inspects backup job status, restores files. |
| **System Evaluator / Professor** | Evaluates cloud architecture, data integrity, deduplication efficiency, and recovery accuracy. | Inspects API endpoints (`/docs`), reviews database schema, verifies backup logs, validates disaster recovery. |

---

## 3. Functional Requirements (FR)

### Module 1: Authentication & Device Management
- **FR-1.1 Standard Authentication:** Secure user registration and login using email and password. (No external SSO or OAuth required).
- **FR-1.2 Password Security:** Passwords must be hashed using industry-standard secure hashing (`bcrypt` or `Argon2id`). Plaintext passwords must never be stored.
- **FR-1.3 Session & Token Management:** Issue JWT (JSON Web Tokens) for authenticated API sessions with standard expiration.
- **FR-1.4 Device Registration:** Client machines register with the backend to receive a unique `device_id` and token, allowing multi-device tracking under one user account.

### Module 2: Backup Engine & Data Processing
- **FR-2.1 Source Directory Selection:** Users can designate one or more local folders for backup, with configurable exclusion rules (e.g., `*.tmp`, `node_modules`, `.git`).
- **FR-2.2 Manual On-Demand Backup:** Users can trigger an immediate backup snapshot at any time via CLI or Web Dashboard.
- **FR-2.3 File-Level Deduplication (Single-Instance Storage):**
  - Compute the SHA-256 checksum for each file candidate.
  - Query the backend index before uploading. If a file with the identical hash already exists in storage, skip the physical upload and link the existing storage object into the new snapshot.
- **FR-2.4 Compression:** Compress eligible files using standard compression (`gzip` or `zstandard`) prior to upload to optimize storage and transfer times.
- **FR-2.5 Integrity Verification:** Compute and store SHA-256 checksums alongside file metadata. Verify file checksums upon restore to guarantee bit-for-bit integrity.

### Module 3: Cloud Storage Operations (GCS & Local Mock)
- **FR-3.1 Pluggable Storage Provider:** Support a unified storage interface with two operational modes configured via environment variables:
  - `STORAGE_PROVIDER=mock`: Stores objects locally on disk, mocking GCS behavior without network or credentials.
  - `STORAGE_PROVIDER=gcs`: Connects to Google Cloud Storage using official Google Cloud client libraries.
- **FR-3.2 Cloud Uploads & Pre-Signed URLs:** Generate secure, short-lived signed URLs for uploads and downloads, decoupling data transfers from API server compute.
- **FR-3.3 Cloud Encryption at Rest:** When running on live GCP, leverage Google Cloud Storage's default server-side encryption (Google-managed AES-256) at rest. All network communications use HTTPS/TLS.
- **FR-3.4 Regional Pricing Verification:** The system must not assume free tier availability for non-US regions. Region and storage class must be explicitly configured in `.env` with cost considerations documented.

### Module 4: Automatic Backup Scheduling
- **FR-4.1 Automated Schedules:** Support background backup triggers:
  - Interval-based (e.g., every 1 hour, every 6 hours).
  - Daily scheduled time (e.g., daily at 02:00 AM).
  - Directory watcher triggers (detecting file additions/changes via `watchdog` with debounce).
- **FR-4.2 Background Agent:** The client backup agent runs as a lightweight background process with minimal CPU and memory (< 100 MB RAM).
- **FR-4.3 Execution Logging:** Record every backup run in a `backup_jobs` table: timestamp, files scanned, files uploaded, files deduplicated, bytes transferred, duration, and status (`SUCCESS`, `FAILED`, `PARTIAL`).

### Module 5: File Versioning & Recovery
- **FR-5.1 Point-in-Time Snapshots:** Every backup creates an immutable snapshot representing the full directory tree at that moment.
- **FR-5.2 Version History:** Users can view the historical versions of any individual file across all past snapshots.
- **FR-5.3 Granular & Full Restore:** Users can restore a single file, a specific folder, or an entire snapshot to its original location or an alternate restore directory.
- **FR-5.4 Deleted-File Recovery (Trash / Soft-Delete):**
  - Identify files present in earlier snapshots that were deleted in the latest local state.
  - Display deleted files in a dedicated "Trash / Deleted Files" view with one-click restoration to the current state.
- **FR-5.5 Conflict Resolution:** When restoring over existing files, provide options: `Overwrite`, `Keep Both (rename with timestamp)`, or `Skip`.

### Module 6: Web Management Console & Monitoring
- **FR-6.1 Overview Dashboard:** View total storage used, files protected, active devices, last backup timestamp, and space saved through deduplication.
- **FR-6.2 Snapshot Time-Machine Explorer:** Browse historical snapshot directory trees through an intuitive web file explorer.
- **FR-6.3 Backup History & Logs:** View historical job execution logs with status filters and error details.
- **FR-6.4 Deleted Files View:** Browse and restore deleted files with a single click.

---

## 4. Non-Functional Requirements (NFR)

### NFR-1: Performance & Resource Efficiency
- **NFR-1.1 Low Memory Footprint:** Background agent must consume $\le 100\text{ MB}$ RAM on an 8–16 GB laptop.
- **NFR-1.2 CPU Throttling:** Background idle state must consume $< 2\%$ CPU.
- **NFR-1.3 Deduplication Speed:** SHA-256 hashing and backend index lookup must process $\ge 100\text{ files/second}$ for typical document/code repositories.

### NFR-2: Reliability & Data Integrity
- **NFR-2.1 100% Bit-for-Bit Integrity:** Restored files must produce the identical SHA-256 hash as the original pre-backup file.
- **NFR-2.2 Atomicity & Crash Consistency:** If a backup job is interrupted, the partial state is marked `INTERRUPTED` without corrupting previous valid snapshots.
- **NFR-2.3 Reference Counting Safety:** Deduplicated files are only deleted from physical storage when no existing snapshots reference them (`ref_count == 0`).

### NFR-3: Security & Privacy
- **NFR-3.1 Transit Security:** All client-server and client-storage communication must use HTTPS (TLS 1.2+).
- **NFR-3.2 Credential Protection:** No cloud credentials, service account keys, or secrets committed to source control. `.env` and `*.json` keys must be in `.gitignore`.
- **NFR-3.3 Cloud Encryption at Rest:** Rely on Google Cloud Storage's built-in default AES-256 server-side encryption.

### NFR-4: Usability & Academic Maintainability
- **NFR-4.1 Zero-Setup Dev Mode:** Running the project with `STORAGE_PROVIDER=mock` and SQLite requires zero external cloud accounts, credit cards, or Docker containers.
- **NFR-4.2 Interactive API Docs:** FastAPI automatically serves interactive Swagger UI documentation at `/docs`.
- **NFR-4.3 Cross-Platform Support:** Backend and agent execute natively on Windows 10/11, macOS, and Linux.

---

## 5. Scope Boundaries (4–6 Week Project)

### In-Scope (Core Priorities):
- Email/password auth with JWT.
- Pluggable storage: Local Mock Storage (dev) + Google Cloud Storage (prod).
- SHA-256 file deduplication and compression.
- Point-in-time snapshots and version history.
- Granular restore and conflict resolution.
- Deleted-file recovery (Soft-Delete / Trash).
- Automated background scheduling (interval/cron/watcher) + manual backup.
- Backup execution logs and history.
- Web dashboard (React) + lightweight agent (Python).

### Out-of-Scope (Excluded for Simplicity & Timely Delivery):
- Client-side zero-knowledge encryption (adds complex key management; deferred in favor of standard HTTPS + GCS server-side encryption).
- Institutional SSO / OAuth / SAML integrations.
- Multi-cloud federation (AWS/Azure sync).
- Bare-metal disk imaging / Volume Shadow Copy (VSS) kernel drivers.
- WORM Bucket Lock enforcement.
