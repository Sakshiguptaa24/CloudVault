# CloudVault: 4–6 Week Development Roadmap & Project Plan
**Project:** CloudVault – Cloud-Based Backup and Recovery System  
**Subject:** Cloud Computing Technology (4–6 Week University Project)  
**Target Completion:** 4 to 6 Weeks  
**Primary Developer Profile:** Beginner with AI-assisted Architecture  
**Hardware Profile:** Windows Laptop (8–16 GB RAM)  
**Author / Project Manager:** Senior Software Architect & Technical PM  
**Status:** Approved Baseline  
**Date:** November 2026  

---

## 1. Project Management Principles

This roadmap is designed for high quality, predictable delivery, and top academic marks:
1. **Zero-Cost, Low-Friction Dev:** All development initially runs with `STORAGE_PROVIDER=mock` and SQLite. No cloud account or credit card is needed to build, run, test, and demonstrate 100% of the functionality.
2. **Modular Weekly Milestones:** Each week delivers an independently runnable subsystem.
3. **Core Feature Focus:** Prioritizes automatic scheduling, point-in-time versioning, deleted-file recovery, manual backup, restore, execution history, and SHA-256 integrity checks.

---

## 2. Sprint Timeline & Work Breakdown Structure (WBS)

```
Week 1: Core Scaffolding, Models, Auth & Mock Storage Provider
   │
Week 2: Deduplication Engine, Compression & Backup Pipeline
   │
Week 3: Point-in-Time Restore, Versioning & Trash Recovery
   │
Week 4: Scheduling Daemon (Timers/Watcher) & Client CLI
   │
Week 5: Web Management Dashboard & Backup History UI
   │
Week 6: Regional Cloud Verification, GCS Integration & Demo Prep
```

---

### Phase 1: Core Scaffolding, Models, Auth & Mock Storage (Week 1)
**Goal:** Running FastAPI backend with database models, email/password JWT auth, and mock storage provider.

- **Tasks:**
  - Initialize project structure (`backend/`, `agent/`, `frontend/`, `data/`).
  - Create `requirements.txt` with locked dependencies (`fastapi`, `uvicorn`, `sqlalchemy`, `pydantic`, `pydantic-settings`, `bcrypt`, `python-jose`, `pytest`).
  - Implement SQLAlchemy models matching [database-design.md](file:///c:/Users/saksh/Desktop/CloudVault/database-design.md).
  - Implement JWT authentication endpoints: `/api/v1/auth/register`, `/api/v1/auth/login`.
  - Implement device registration: `/api/v1/devices/register`.
  - Implement `StorageProvider` base interface and `MockStorageProvider` (stores objects in `./data/mock_storage/` with emulated URLs).
- **Deliverable:** Backend running at `http://localhost:8000/docs` with working registration, login, and device enrollment.

---

### Phase 2: Deduplication Engine, Compression & Backup Pipeline (Week 2)
**Goal:** Client agent discovers files, deduplicates via SHA-256, compresses, and commits point-in-time snapshots.

- **Tasks:**
  - Build recursive file scanner with glob pattern exclusions (`*.tmp`, `node_modules`, `.git`).
  - Implement streaming SHA-256 hasher (64 KB chunks).
  - Implement deduplication check endpoint (`POST /api/v1/backups/check-hash`):
    - Skip physical upload if hash already exists in storage (0-byte transfer).
  - Implement compression utility (`gzip` / `zstandard`).
  - Implement upload coordinator (streams compressed file to storage endpoint).
  - Implement snapshot committer (`POST /api/v1/snapshots/commit`): creates snapshot record and links `snapshot_files`.
- **Deliverable:** Working Python backup script that backs up a local test directory, skips duplicates, and saves snapshot trees.

---

### Phase 3: Point-in-Time Restore, Versioning & Trash Recovery (Week 3)
**Goal:** Restore files to any historical version with verified checksums, and recover accidentally deleted files.

- **Tasks:**
  - Implement snapshot tree query endpoint (`GET /api/v1/snapshots/{id}/tree`).
  - Implement granular file restore workflow:
    - Download compressed object from storage.
    - Decompress payload.
    - Compute SHA-256 of restored file and verify against original stored hash.
    - Write to target location with conflict policy (`overwrite`, `rename`, `skip`).
  - Implement Deleted-File Recovery API (`GET /api/v1/recovery/deleted-files`):
    - Identify files present in earlier snapshots but deleted in the latest snapshot.
    - Provide restore endpoint to resurrect deleted files into active directory.
- **Deliverable:** Full round-trip backup and restore capability with 100% verified checksum matching and trash recovery.

---

### Phase 4: Scheduling Daemon (Timers/Watcher) & Client CLI (Week 4)
**Goal:** Package the backup engine into an autonomous background service and a command-line interface.

- **Tasks:**
  - Build `cloudvault` CLI tool (using `typer` or `argparse`):
    - `cloudvault login`
    - `cloudvault backup <folder> --name <plan>`
    - `cloudvault restore <snapshot_id> --to <dest>`
    - `cloudvault daemon start`
  - Implement automated scheduler using `APScheduler`:
    - Support interval triggers (every N hours) and cron expressions.
  - Implement directory watcher using `watchdog`:
    - Listen for file system events with a 5-second debounce.
  - Implement execution logging: records every run in `backup_jobs` table.
- **Deliverable:** Lightweight background daemon running on Windows, logging jobs, and triggering backups automatically.

---

### Phase 5: Web Management Dashboard (Week 5)
**Goal:** Modern React single-page dashboard for visual backup management and academic demonstration.

- **Tasks:**
  - Initialize React + Vite + Tailwind CSS dashboard (`frontend/`).
  - **Overview Page:** Summary cards (storage used, deduplication savings, active devices, last backup status).
  - **Time Machine Explorer:** Visual directory tree navigator with historical date slider.
  - **Backup History:** Table of past backup jobs with status chips, duration, and error logs.
  - **Trash / Deleted Files Page:** Table of deleted files with one-click restore.
  - **Manual Backup Button:** Trigger an immediate backup snapshot from the browser.
- **Deliverable:** Polished web UI running on `http://localhost:5173` demonstrating the complete system.

---

### Phase 6: Cloud Verification, GCS Integration & Demo Prep (Week 6)
**Goal:** Configure Google Cloud Storage integration, execute disaster recovery drills, and finalize presentation.

- **Tasks:**
  - Implement `GCSStorageProvider` using `google-cloud-storage` SDK.
  - Verify regional pricing: select eligible free-tier region (`us-central1`) or confirm minimal spend (< \$0.05) if using another region.
  - Set up GCP Budget Alert (\$1.00 limit).
  - Conduct Disaster Recovery Simulation:
    - Delete test folder $\rightarrow$ trigger restore $\rightarrow$ verify 100% SHA-256 match.
  - Prepare academic demonstration materials:
    - System architecture slides.
    - 5-minute live demo script.
- **Deliverable:** Production-ready system with verified cloud integration, test reports, and presentation slides.

---

## 3. Risk Management & Safeguards

| Risk | Impact | Mitigation |
|---|---|---|
| **Accidental Cloud Billing** | Financial | Use `STORAGE_PROVIDER=mock` for all initial development. Verify regional pricing before switching to live GCS. Set \$1.00 budget alert. |
| **Credential Leakage** | Security | Keep all keys in `.env` and service account `.json` outside git. Verify `.gitignore` rules. |
| **Windows File Locking** | Reliability | Implement non-blocking read with retry backoff for open files. |
| **Memory Pressure (8–16 GB RAM)** | Performance | Stream files in 64 KB buffers. Avoid heavy JVM / Docker dependencies. |
