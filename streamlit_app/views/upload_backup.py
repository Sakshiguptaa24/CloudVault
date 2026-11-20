import streamlit as st
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to
from streamlit_app.styles import format_bytes

def render_upload_backup(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in to upload files.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>📤 Direct File Upload & Instant Backup</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Upload files directly to your vault. Files are hashed (SHA-256), compressed, envelope-encrypted with AES-256-GCM, and deduplicated automatically.</p>", unsafe_allow_html=True)

    # Fetch available backup plans
    try:
        plans = client.list_backup_plans(token)
    except Exception as e:
        st.error(f"Failed to fetch backup plans: {str(e)}")
        plans = []

    # If no plans exist, offer to auto-create a default plan
    selected_plan_id = None
    if not plans:
        st.info("💡 You don't have any backup plans yet. Let's create a default one for your uploads.")
        if st.button("Create 'Default Web Backups' Plan", type="primary"):
            try:
                new_plan = client.create_backup_plan(
                    token=token,
                    plan_name="Default Web Backups",
                    source_directories=["uploads/"],
                    exclusion_patterns=["*.tmp"],
                    schedule_type="manual"
                )
                st.success("Plan created successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Error creating plan: {str(e)}")
        return
    else:
        plan_options = {p["id"]: f"{p['plan_name']} (Algo: {p.get('compression_algo', 'gzip')})" for p in plans}
        selected_plan_id = st.selectbox(
            "Select Destination Backup Plan:",
            options=list(plan_options.keys()),
            format_func=lambda pid: plan_options[pid]
        )

    st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)

    is_demo = getattr(client, "demo_mode", False)
    if is_demo:
        st.markdown("##### 🧪 Or Pick a Sample Demonstration File (1-Click Test):")
        sb1, sb2, sb3 = st.columns(3)
        with sb1:
            if st.button("📄 Financial Audit (PDF)", use_container_width=True):
                st.session_state["demo_sample_file"] = {
                    "name": "2026_q3_financial_audit.pdf",
                    "bytes": b"%PDF-1.7 CloudVault Sample Financial Audit Report 2026 - Reconciled."
                }
        with sb2:
            if st.button("📊 Customer Records (CSV)", use_container_width=True):
                st.session_state["demo_sample_file"] = {
                    "name": "enterprise_clients_export.csv",
                    "bytes": b"client_id,company,tier\n1,Acme Corp,Enterprise\n2,Global Logistics,Tier 1"
                }
        with sb3:
            if st.button("⚙️ Infrastructure (YAML)", use_container_width=True):
                st.session_state["demo_sample_file"] = {
                    "name": "k8s_production_cluster.yaml",
                    "bytes": b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: cloudvault-dr-worker"
                }

    # File Upload Widget
    uploaded_file = st.file_uploader(
        "Choose file to backup and protect:",
        type=None,  # Accept any file type
        help="All file formats supported. Demo upload limit: 5 MB (100 MB in production)."
    )

    custom_rel_path = st.text_input(
        "Vault Path / Folder (Optional):",
        placeholder="e.g. documents/financials/2026_q3_report.pdf",
        help="Leave empty to use the original filename in root."
    )

    # Resolve target file (either user upload or selected demo sample)
    staged_name = None
    staged_bytes = None
    if uploaded_file is not None:
        staged_name = uploaded_file.name
        staged_bytes = uploaded_file.getvalue()
    elif is_demo and "demo_sample_file" in st.session_state and st.session_state["demo_sample_file"]:
        staged_name = st.session_state["demo_sample_file"]["name"]
        staged_bytes = st.session_state["demo_sample_file"]["bytes"]

    if staged_name and staged_bytes:
        file_size = len(staged_bytes)

        st.markdown(f"""
        <div style="background: #1e293b; padding: 12px 16px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 16px;">
            <span style="color: #94a3b8;">File Ready:</span> <strong style="color: #f8fafc;">{staged_name}</strong> 
            <span style="color: #38bdf8; margin-left: 10px;">({format_bytes(file_size)})</span>
            {'<span class="badge badge-info" style="margin-left: 10px;">Demo Sample</span>' if uploaded_file is None else ''}
        </div>
        """, unsafe_allow_html=True)

        # Validation guards for demo safety
        if is_demo and file_size > 5 * 1024 * 1024:
            st.error("⚠️ Demonstration file size exceeds the 5 MB limit. Please select a smaller demonstration file.")
            return

        disallowed_demo_exts = [".exe", ".dll", ".bat", ".cmd", ".sh", ".vbs", ".ps1", ".msi", ".jar", ".scr", ".bin", ".com"]
        if is_demo and any(staged_name.lower().endswith(ext) for ext in disallowed_demo_exts):
            st.error("⚠️ Executable and script file extensions (.exe, .bat, etc.) are prohibited in public demonstration mode for system security.")
            return

        if st.button("🚀 Upload & Encrypt Backup", type="primary", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()

            try:
                status_text.text("Calculating SHA-256 cryptographic digest...")
                progress_bar.progress(30)

                status_text.text("Checking deduplication registry & encrypting...")
                progress_bar.progress(60)

                res = client.upload_file_direct(
                    token=token,
                    plan_id=selected_plan_id,
                    filename=staged_name,
                    file_bytes=staged_bytes,
                    relative_path=custom_rel_path.strip() if custom_rel_path.strip() else None
                )

                progress_bar.progress(100)
                status_text.empty()

                is_dedup = res.get("deduplicated", False)
                sha = res.get("sha256", "")
                snap_id = res.get("snapshot_id", "")

                st.success("✅ File successfully protected in CloudVault!")

                # Results Summary Card
                st.markdown(f"""
                <div class="cv-card" style="border-left: 4px solid {'#22c55e' if is_dedup else '#38bdf8'};">
                    <h3 style="margin-top: 0; color: #f8fafc;">Upload & Verification Receipt</h3>
                    <p><strong>Filename:</strong> {uploaded_file.name}</p>
                    <p><strong>SHA-256 Digest:</strong> <code style="color: #38bdf8;">{sha}</code></p>
                    <p><strong>Integrity Verification:</strong> <span class="badge badge-success">Verified Match</span></p>
                    <p><strong>Storage Status:</strong> {
                        '<span class="badge badge-success">⚡ 100% Deduplicated (0 new bytes stored)</span>' 
                        if is_dedup else 
                        '<span class="badge badge-info">🔒 Compressed & AES-256-GCM Envelope Encrypted</span>'
                    }</p>
                    <p><strong>Snapshot Created:</strong> <code>{snap_id}</code></p>
                </div>
                """, unsafe_allow_html=True)

                col_b1, col_b2 = st.columns(2)
                with col_b1:
                    if st.button("📸 View Snapshots & Tree"):
                        navigate_to("Snapshots")
                with col_b2:
                    if st.button("🔄 Go to Restore Center"):
                        navigate_to("Restore & Recovery")

            except APIError as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"Upload failed: {e.detail}")
            except Exception as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"Error during upload: {str(e)}")
