import streamlit as st
from streamlit_app.api_client import CloudVaultClient
from streamlit_app.session import navigate_to, is_authenticated

def render_landing(client: CloudVaultClient):
    st.markdown("""
    <div style="text-align: center; padding: 40px 20px 20px 20px;">
        <h1 style="font-size: 3rem; font-weight: 800; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            ☁️ CloudVault 2.0
        </h1>
        <p style="font-size: 1.25rem; color: #94a3b8; max-width: 750px; margin: 0 auto 24px auto;">
            Zero-Trust Multi-Cloud Backup, Intelligent Ransomware Defense, and Autonomous Disaster Recovery Platform
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Check live backend connection
    try:
        health = client.health_check()
        storage_name = health.get("storage_provider", "mock").upper()
        version = health.get("version", "2.0.0")
        st.markdown(f"""
        <div style="display: flex; justify-content: center; gap: 12px; margin-bottom: 30px;">
            <span class="badge badge-success">● Backend Online (v{version})</span>
            <span class="badge badge-info">Storage Engine: {storage_name}</span>
            <span class="badge badge-success">Zero-Trust AES-256-GCM</span>
        </div>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.markdown("""
        <div style="display: flex; justify-content: center; gap: 12px; margin-bottom: 30px;">
            <span class="badge badge-danger">● Backend Disconnected</span>
            <span class="badge badge-warning">Waiting for API server</span>
        </div>
        """, unsafe_allow_html=True)

    # Call to action
    col_c1, col_c2, col_c3 = st.columns([1, 2, 1])
    with col_c2:
        if is_authenticated():
            if st.button("🚀 Enter Disaster Recovery Dashboard", use_container_width=True, type="primary"):
                navigate_to("Dashboard")
        else:
            c_btn1, c_btn2 = st.columns(2)
            with c_btn1:
                if st.button("✨ Create Free Account", use_container_width=True, type="primary"):
                    navigate_to("Register")
            with c_btn2:
                if st.button("🔐 Sign In", use_container_width=True):
                    navigate_to("Login")

    st.markdown("<hr style='border-color: #1e293b; margin: 40px 0;'>", unsafe_allow_html=True)

    # Feature Grid
    st.subheader("🛡️ Enterprise Capabilities Built Into CloudVault 2.0")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        <div class="cv-card">
            <h3 style="color: #38bdf8; font-size: 1.2rem; margin-top: 0;">🌐 Multi-Cloud Resilience</h3>
            <p style="color: #94a3b8; font-size: 0.95rem;">
                Standardized abstraction across Google Cloud Storage, Amazon S3, Azure Blob, and Local Mock with automated multi-cloud failover and latency health routing.
            </p>
            <span class="badge badge-info">Multi-Cloud Ready</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="cv-card">
            <h3 style="color: #38bdf8; font-size: 1.2rem; margin-top: 0;">⚡ Instant Deduplication</h3>
            <p style="color: #94a3b8; font-size: 0.95rem;">
                Client-side SHA-256 cryptographic chunking. Identical objects never re-upload, cutting bandwidth and cloud storage costs by up to 80%.
            </p>
            <span class="badge badge-success">Zero Egress Waste</span>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="cv-card">
            <h3 style="color: #38bdf8; font-size: 1.2rem; margin-top: 0;">🔒 Envelope Encryption & WORM</h3>
            <p style="color: #94a3b8; font-size: 0.95rem;">
                Military-grade AES-256-GCM envelope encryption with per-user PBKDF2 key derivation and immutable WORM retention locks against unauthorized tampering.
            </p>
            <span class="badge badge-success">Zero-Trust Security</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="cv-card">
            <h3 style="color: #38bdf8; font-size: 1.2rem; margin-top: 0;">🤖 AI Disaster Recovery Copilot</h3>
            <p style="color: #94a3b8; font-size: 0.95rem;">
                Intelligent assistant with intent-aware diagnostics: live RPO/RTO telemetry, recovery plan generation, and HMAC-authenticated execution cards.
            </p>
            <span class="badge badge-info">AI-Powered Ops</span>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class="cv-card">
            <h3 style="color: #38bdf8; font-size: 1.2rem; margin-top: 0;">🚨 Ransomware Anomaly Shield</h3>
            <p style="color: #94a3b8; font-size: 0.95rem;">
                Real-time Shannon entropy scanning, suspicious extension trapping, burst-modification detection, and reversible quarantine for corrupted snapshots.
            </p>
            <span class="badge badge-danger">Proactive Defense</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="cv-card">
            <h3 style="color: #38bdf8; font-size: 1.2rem; margin-top: 0;">📈 Predictive Analytics</h3>
            <p style="color: #94a3b8; font-size: 0.95rem;">
                Linear regression storage forecasting, quota exhaustion countdown, cloud cost comparisons, and automated executive PDF/Markdown reports.
            </p>
            <span class="badge badge-warning">Predictive AI</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<hr style='border-color: #1e293b; margin: 40px 0;'>", unsafe_allow_html=True)

    # Interactive Architecture Diagram / Specs
    st.subheader("📐 Architecture & Multi-Tenant Isolation")
    st.code("""
  +-----------------------------------------------------------------------------------+
  |                       Streamlit Multi-User Web Client                              |
  |  (State-Isolated Sessions: Per-User JWT in st.session_state, Zero Cross-Leakage)  |
  +-----------------------------------------+-----------------------------------------+
                                            | HTTPS / Bearer JWT
                                            v
  +-----------------------------------------------------------------------------------+
  |                         CloudVault FastAPI Core Gateway                           |
  |   - OAuth2 / JWT Auth (RFC 6238 TOTP MFA & SHA-256 Recovery Codes)                |
  |   - Multi-Tenant Row-Level Security (Strict user_id foreign key validation)       |
  |   - Rate Limiting, CORS, Audit Chaining & Security Headers                        |
  +-------------------+---------------------------------------+-----------------------+
                      |                                       |
                      v                                       v
  +------------------------------------+    +-----------------------------------------+
  |  Relational Database Engine        |    | Multi-Cloud Object Storage Router       |
  |  - Managed PostgreSQL (Supabase/RDS)|    | - Google Cloud Storage (GCS)            |
  |  - SQLite (Local Dev / Offline)    |    | - Amazon S3                             |
  |  - Tamper-Evident Hash Chains      |    | - Microsoft Azure Blob Storage          |
  +------------------------------------+    | - Local Mock Storage (Zero-Cost Dev)    |
                                            +-----------------------------------------+
    """, language="text")
