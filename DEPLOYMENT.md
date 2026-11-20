# CloudVault 2.0 – Production Deployment & Operations Guide

This guide details how to run, tunnel, and deploy **CloudVault 2.0 (Intelligent Cloud Backup, Security & Disaster Recovery Platform)** to the public internet with full mobile responsiveness, Progressive Web App (PWA) installation, AI Copilot, and production-grade security.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |   Mobile / Tablet / Desktop Clients   |
                      |   (PWA Standalone or Browser)         |
                      +---------------------------------------+
                                          |
                                          | HTTPS / TLS 1.3
                                          v
                      +---------------------------------------+
                      |   Public Cloud / Edge Reverse Proxy   |
                      |   (Cloud Run / Render / Cloudflare)   |
                      +---------------------------------------+
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
             +---------------------+             +---------------------+
             |  Static PWA Assets  |             |    FastAPI Core     |
             |  - Manifest, SW     |             |  - Deduplication    |
             |  - HTML / CSS / JS  |             |  - Snapshots & Auth |
             |  - Offline Fallback |             |  - Integrity Verify |
             +---------------------+             +---------------------+
                                                            |
                                      +---------------------+---------------------+
                                      |                                           |
                                      v                                           v
                           +----------------------+                    +----------------------+
                           |   Metadata Storage   |                    |   Blob / Payload     |
                           |   (SQLite / Postgres)|                    |   - Local Mock Storage|
                           |                      |                    |   - Google Cloud (GCS)|
                           +----------------------+                    +----------------------+
```

---

## 1. Instant Public Access from Local Machine (Zero-Setup Tunnel)

If you are running CloudVault locally on Windows (`http://localhost:8000`) and need an immediate public HTTPS URL to demonstrate the mobile experience on phones or tablets:

### Method A: One-Click SSH Reverse Tunnel (Built-in to Windows OpenSSH)
CloudVault includes ready-to-run tunnel scripts in the project root:
- Run via PowerShell:
  ```powershell
  .\tunnel.ps1
  ```
- Or run via Command Prompt:
  ```cmd
  tunnel.bat
  ```
- Or run manually:
  ```cmd
  ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run
  ```
The terminal will display an active public HTTPS address (e.g. `https://xxxxxx.lhr.life`). Open this address on your smartphone or share it with university evaluators.

### Method B: Cloudflare Tunnel (Official CLI)
```cmd
winget install --id Cloudflare.cloudflared
cloudflared tunnel --url http://localhost:8000
```
Generates a persistent `https://*.trycloudflare.com` domain with automatic SSL certificates.

---

## 2. Google Cloud Run Deployment (Official GCP Alignment)

Because CloudVault is designed for **Google Cloud**, Cloud Run is the recommended production deployment target.

### Step 1: Pre-requisites
- [Google Cloud SDK (gcloud CLI)](https://cloud.google.com/sdk/docs/install) installed.
- Active Google Cloud project with billing enabled (Cloud Run has a generous free tier of 2 million requests/month).

### Step 2: One-Command Deployment
CloudVault includes automated deployment scripts:
- **PowerShell:**
  ```powershell
  .\deploy_cloudrun.ps1 -ProjectId "your-gcp-project-id" -Region "us-central1"
  ```
- **Bash / Linux / macOS:**
  ```bash
  chmod +x deploy_cloudrun.sh
  ./deploy_cloudrun.sh "your-gcp-project-id" "us-central1"
  ```

### Manual `gcloud` Execution Steps:
```bash
# 1. Select your project
gcloud config set project your-gcp-project-id

# 2. Enable necessary GCP APIs
gcloud services enable run.googleapis.com cloudbuild.googleapis.com containerregistry.googleapis.com

# 3. Build & submit Docker image
gcloud builds submit --tag gcr.io/your-gcp-project-id/cloudvault:latest

# 4. Deploy to Cloud Run
gcloud run deploy cloudvault \
  --image gcr.io/your-gcp-project-id/cloudvault:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8000 \
  --memory 512Mi \
  --cpu 1 \
  --set-env-vars "STORAGE_PROVIDER=mock,ALLOWED_ORIGINS=*"
```
Once completed, Google Cloud will output a public HTTPS endpoint, such as `https://cloudvault-xyz-uc.a.run.app`.

---

## 3. Render Deployment (1-Click Blueprint)

CloudVault includes a pre-configured `render.yaml` Blueprint for zero-friction cloud deployment.

1. Push your repository to **GitHub** or **GitLab**.
2. Go to [dashboard.render.com](https://dashboard.render.com/) and click **New > Blueprint**.
3. Select your CloudVault repository.
4. Render will automatically read `render.yaml`, build the Docker container, run database migrations, and deploy the service on a free HTTPS subdomain (e.g. `https://cloudvault.onrender.com`).

---

## 4. Railway / Docker Deployments

Deploy using the provided `Dockerfile` and `Procfile`:
```bash
# Build locally
docker build -t cloudvault:latest .

# Run container
docker run -d -p 8000:8000 -e STORAGE_PROVIDER=mock -v cloudvault_data:/app/data cloudvault:latest
```

---

## 5. Storage & Database Persistence Strategy

| Component | Development / Demo | Production Deployment |
| :--- | :--- | :--- |
| **Database** | SQLite (`data/cloudvault.db`) | Managed PostgreSQL (Render Postgres, Supabase, Neon, or Cloud SQL) |
| **Object Storage** | Local Mock Storage (`data/mock_storage`) | Google Cloud Storage (Bucket with CMEK/Standard Class) |
| **Database URL** | `sqlite:///data/cloudvault.db` | `postgresql://user:pass@host:5432/dbname` |

### Configuring PostgreSQL
When deploying to cloud environments where filesystems are ephemeral:
1. Create a free PostgreSQL database on **Neon.tech**, **Supabase**, or **Render**.
2. Supply the connection string via the `DATABASE_URL` environment variable:
   ```env
   DATABASE_URL=postgresql://user:password@ep-sample.us-east-1.aws.neon.tech/cloudvault?sslmode=require
   ```
CloudVault's SQLAlchemy engine detects PostgreSQL automatically, enables connection pooling, and initializes tables on boot.

---

## 6. Google Cloud Storage (GCS) Configuration

To transition from Local Mock Storage to live Google Cloud Storage:

### Option A: Service Account Key File (Standard)
1. In Google Cloud Console, navigate to **IAM & Admin > Service Accounts**.
2. Create a service account with `roles/storage.objectAdmin` on your bucket.
3. Download the JSON key file.
4. Configure `.env`:
   ```env
   STORAGE_PROVIDER=gcs
   GCS_BUCKET_NAME=my-cloudvault-backups
   GCS_PROJECT_ID=my-gcp-project
   GOOGLE_APPLICATION_CREDENTIALS=/path/to/keyfile.json
   GCS_REGION=us-central1
   ```

### Option B: Inline JSON Credentials (Ideal for PaaS / Cloud Run / Render)
Instead of mounting files, pass the JSON key directly as a secret:
```env
GCS_CREDENTIALS_JSON={"type":"service_account","project_id":"my-project",...}
```

---

## 7. Progressive Web App (PWA) Installation

CloudVault is compliant with the W3C Web App Manifest and Service Worker specifications.

- **Android (Chrome):** Visit the public HTTPS URL. A prompt will appear at the bottom: *"Add CloudVault to Home screen"*, or click the **📲 Install App** button in the top navigation bar.
- **iOS / iPadOS (Safari):** Tap the **Share** button in Safari and select **Add to Home Screen**. CloudVault will launch as a standalone application without browser chrome.
- **Desktop (Chrome / Edge):** Click the install icon in the address bar or the **📲 Install App** button. CloudVault will run in its own dedicated window with dark-mode titlebar styling.

### Strict PWA Security Controls
- **Zero Sensitive Caching:** The service worker (`sw.js`) explicitly ignores and bypasses all `/api/*` endpoints and non-GET requests.
- **Offline Protection:** If network connectivity is lost, CloudVault immediately renders the custom `offline.html` page and warns the user that backup and restore operations require active cloud connectivity. No plaintext user files or tokens are ever retained in browser caches.

---

## 9. Streamlit Community Cloud Deployment (Zero-Cost Public Interface)

CloudVault 2.0 features a dedicated multi-user **Streamlit frontend** deployable with 1 click to [Streamlit Community Cloud](https://share.streamlit.io).

### Architecture
- **Frontend**: Streamlit Community Cloud (`https://<your-subdomain>.streamlit.app`)
- **Backend API**: FastAPI running on Render, Railway, Google Cloud Run, or VPS (`https://<your-backend>.onrender.com`)
- **Database**: Managed PostgreSQL on Supabase or Neon (`DATABASE_URL=postgresql://...`)
- **Storage**: Multi-Cloud (Mock Storage for zero-cost demo, or GCS / S3 / Azure)

### Step-by-Step Deployment:
1. **Push your repository to GitHub**:
   ```bash
   git add .
   git commit -m "feat(streamlit): deployment ready"
   git push origin master
   ```

2. **Deploy the FastAPI Backend**:
   - Deploy backend to Render, Railway, or Google Cloud Run.
   - Set environment variables on the backend:
     ```env
     DATABASE_URL=postgresql://user:pass@host:5432/cloudvault
     STORAGE_PROVIDER=mock
     SECRET_KEY=generate-a-strong-random-secret
     ALLOWED_ORIGINS=*
     ```
   - Note the deployed HTTPS URL (e.g. `https://cloudvault-api.onrender.com`).

3. **Deploy the Streamlit UI to Streamlit Community Cloud**:
   - Sign in to [share.streamlit.io](https://share.streamlit.io/) with your GitHub account.
   - Click **Create App** > **Deploy a public app from GitHub**.
   - Select your repository: `username/CloudVault` (or your repo name).
   - Branch: `master`.
   - Main file path: `streamlit_app.py` (or `app.py`).
   - Click **Advanced settings...** and add your backend connection secret:
     ```toml
     [general]
     BACKEND_API_URL = "https://cloudvault-api.onrender.com"
     ```
   - Click **Deploy!**
   - Streamlit will install dependencies from `requirements.txt` and launch the app at `https://<your-app>.streamlit.app`.

### Local Development / Offline Testing:
To run both backend and Streamlit locally:
```bash
# Terminal 1: Run FastAPI backend
python cli.py serve --port 8000

# Terminal 2: Run Streamlit frontend
python cli.py ui --port 8501
# Or directly:
streamlit run streamlit_app.py
```
Open `http://localhost:8501` in your browser.

---

## 10. Multi-Cloud Storage Deployment (S3, GCS, Azure, and Mock)

CloudVault supports dynamic routing and automatic failover across 4 storage backends:

```env
# Multi-Cloud Routing Configuration
STORAGE_PROVIDER=mock          # Options: 'mock', 'gcs', 's3', 'azure'
STORAGE_SECONDARY_PROVIDER=s3  # Automatic failover destination
STORAGE_FAILOVER_ENABLED=True  # Enables transparent multi-cloud failover
STORAGE_MAX_RETRIES=3
STORAGE_TIMEOUT_SECONDS=10
```

1. **Local Air-Gapped Mock (Default)**: Free, zero external credentials required, stores objects in `data/mock_storage/objects`.
2. **Google Cloud Storage (GCS)**: Configure `GCS_BUCKET_NAME`, `GCS_PROJECT_ID`, and service account JSON credentials.
3. **Amazon Web Services (S3)**: Configure `AWS_S3_BUCKET`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`.
4. **Microsoft Azure Blob Storage**: Configure `AZURE_CONTAINER` and `AZURE_STORAGE_CONNECTION_STRING`.


- **Security Headers:** Automatic `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **Upload Restrictions:** 100 MB maximum file size enforcement with HTTP 413 error reporting.
- **Path Sanitization:** All incoming filenames stripped of directory traversal sequences (`../`, `..\`) via `os.path.basename`.
- **User Data Isolation:** Database-level queries enforce `user_id` filtering on snapshots, plans, devices, and restore targets.
- **Hash Integrity:** Every restored payload is decompressed and compared against its SHA-256 fingerprint before delivery.

