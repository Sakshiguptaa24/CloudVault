import streamlit as st
import pandas as pd
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to

def render_security_center(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>🛡️ Intelligent Security & Anomaly Defense Center</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Monitor ransomware threats, inspect cryptographic audit trails, manage envelope encryption keys, and enforce MFA.</p>", unsafe_allow_html=True)

    sec_tab1, sec_tab2, sec_tab3, sec_tab4 = st.tabs([
        "🚨 Ransomware Shield & Alerts",
        "⛓️ Tamper-Evident Audit Trail",
        "🔐 Envelope Encryption & KEK",
        "📱 Multi-Factor Authentication (MFA)"
    ])

    # -------------------------------------------------------------
    # TAB 1: Ransomware Shield & Alerts
    # -------------------------------------------------------------
    with sec_tab1:
        st.subheader("Ransomware Anomaly Protection")
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Detection Engine", "ACTIVE", "Heuristic + Entropy")
        with c2:
            st.metric("Entropy Cutoff", "7.50 / 8.00", "Shannon Entropy")
        with c3:
            st.metric("Burst Limit", "20 files/sec", "Rapid Modification")

        st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)

        st.subheader("Active Security Alerts")
        try:
            alerts = client.list_security_alerts(token, status="ALL")
        except Exception as e:
            st.error(f"Failed to fetch alerts: {str(e)}")
            alerts = []

        if not alerts:
            st.success("✅ No security alerts detected! Your vault environment is clean.")
        else:
            for a in alerts:
                status_color = "#ef4444" if a.get("status") == "ACTIVE" else "#22c55e"
                with st.expander(f"⚠️ {a.get('alert_type', 'Ransomware Alert')} — Risk Score: {a.get('risk_score', 0)}/100 (Status: {a.get('status')})", expanded=(a.get("status") == "ACTIVE")):
                    st.markdown(f"**Created:** {a.get('created_at', '')[:19].replace('T', ' ')}")
                    st.markdown(f"**Reasons:** {', '.join(a.get('reasons', []))}")
                    st.markdown(f"**Quarantined Snapshots:** {len(a.get('affected_snapshot_ids', []))}")

                    if a.get("status") == "ACTIVE":
                        res_notes = st.text_input("Resolution Notes:", value="Verified safe after administrator review", key=f"notes_{a['id']}")
                        if st.button("Resolve Threat & Unquarantine Snapshots", key=f"res_{a['id']}", type="primary"):
                            try:
                                client.resolve_alert(token, a["id"], resolution_notes=res_notes, unquarantine_snapshots=True)
                                st.success("Alert resolved and snapshots restored to active status!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Resolution failed: {str(e)}")

        st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)

        st.subheader("🧪 Safe Ransomware Sandbox Simulation")
        st.markdown("<p style='color: #94a3b8;'>Execute a 100% safe, non-destructive synthetic attack test inside a temporary isolated sandbox. Real user files and backups are never touched.</p>", unsafe_allow_html=True)
        
        scenario = st.selectbox("Select Attack Scenario:", ["mass_encryption", "suspicious_extension", "high_entropy_archive"])
        if st.button("🚀 Run Safe Sandbox Attack Simulation", type="secondary"):
            with st.spinner("Simulating attack in isolated sandbox and evaluating detector..."):
                try:
                    sim_res = client.simulate_attack_test(token, scenario_type=scenario)
                    st.success(f"Simulation completed! Detected: {sim_res.get('alert_triggered')} (Risk Score: {sim_res.get('risk_score')}/100)")
                    st.json(sim_res)
                except Exception as e:
                    st.error(f"Simulation failed: {str(e)}")

        st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)
        st.subheader("🔬 Interactive Shannon Entropy Analyzer")
        st.markdown("<p style='color: #94a3b8;'>Type, paste, or select sample text to calculate Shannon Entropy H in real-time. Values &ge; 7.50 indicate high randomness (strong encryption or compression).</p>", unsafe_allow_html=True)

        sample_entropy_choice = st.selectbox(
            "Quick Sample:",
            ["Custom Input", "Plaintext English (Expected H ~4.1)", "Structured JSON (Expected H ~4.7)", "Simulated Ransomware Ciphertext (Expected H ~7.92)"]
        )
        if sample_entropy_choice == "Plaintext English (Expected H ~4.1)":
            default_text = "CloudVault 2.0 provides continuous data protection, disaster recovery, and ransomware shielding for cloud infrastructure."
        elif sample_entropy_choice == "Structured JSON (Expected H ~4.7)":
            default_text = '{"vault": "production", "snapshots": 14, "encryption": "AES-256-GCM", "rto_target_seconds": 300, "status": "optimal"}'
        elif sample_entropy_choice == "Simulated Ransomware Ciphertext (Expected H ~7.92)":
            import os
            default_text = os.urandom(128).hex()
        else:
            default_text = ""

        calc_input = st.text_area("Input Text or Data:", value=default_text, height=80)
        if calc_input:
            from streamlit_app.demo_service import calculate_shannon_entropy
            h_val = calculate_shannon_entropy(calc_input.encode("utf-8"))
            is_suspicious = h_val >= 7.50
            h_col1, h_col2 = st.columns([1, 2])
            with h_col1:
                st.metric("Calculated Shannon Entropy", f"{h_val:.2f} / 8.00 bits/byte")
            with h_col2:
                if is_suspicious:
                    st.markdown("""
                    <div style="padding-top: 10px;">
                        <span class="badge badge-danger">🚨 HIGH RANDOMNESS / POTENTIAL CIPHERTEXT</span>
                        <div style="font-size: 0.8rem; color: #f87171; margin-top: 4px;">Exceeds ransomware anomaly threshold (7.50). Triggers automated snapshot quarantine.</div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div style="padding-top: 10px;">
                        <span class="badge badge-success">✅ NORMAL TEXT / LOW ENTROPY</span>
                        <div style="font-size: 0.8rem; color: #4ade80; margin-top: 4px;">Below anomaly threshold (7.50). Classified as clean plaintext or structured code.</div>
                    </div>
                    """, unsafe_allow_html=True)

    # -------------------------------------------------------------
    # TAB 2: Tamper-Evident Audit Trail
    # -------------------------------------------------------------
    with sec_tab2:
        st.subheader("Cryptographic Hash-Chained Audit Trail")
        st.markdown("<p style='color: #94a3b8;'>Every security, backup, recovery, and auth operation is immutably recorded with SHA-256 hash chaining (similar to a blockchain ledger).</p>", unsafe_allow_html=True)

        if st.button("🔍 Mathematically Verify Entire Hash Chain", type="primary"):
            with st.spinner("Traversing hash chain from genesis block to head..."):
                try:
                    ver_res = client.verify_audit_trail(token)
                    if ver_res.get("valid"):
                        st.success(f"✅ Cryptographic Integrity Verified! Total Verified Events: {ver_res.get('total_events', 0)}. No tamper, reordering, or deletion detected.")
                    else:
                        st.error(f"❌ Verification Alert: {ver_res.get('message')}")
                except Exception as e:
                    st.error(f"Verification error: {str(e)}")

        try:
            audit_data = client.list_audit_logs(token, limit=50)
            logs = audit_data.get("audit_logs", [])
        except Exception:
            logs = []

        if logs:
            table_logs = []
            for l in logs:
                table_logs.append({
                    "Timestamp": l.get("created_at")[:19].replace("T", " "),
                    "Event Type": l.get("event_type"),
                    "Severity": l.get("severity"),
                    "Action": l.get("action"),
                    "Hash": (l.get("current_hash") or "")[:12] + "..."
                })
            st.dataframe(pd.DataFrame(table_logs), use_container_width=True)
        else:
            st.info("No audit logs found yet.")

    # -------------------------------------------------------------
    # TAB 3: Envelope Encryption & Key Management
    # -------------------------------------------------------------
    with sec_tab3:
        st.subheader("Client-Side Envelope Encryption (AES-256-GCM)")
        try:
            crypto_status = client.get_crypto_status(token)
        except Exception:
            crypto_status = {}

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Cipher Algorithm", "AES-256-GCM", "Authenticated")
        with c2:
            st.metric("Key Derivation", "PBKDF2-SHA256", "100k Iterations")
        with c3:
            st.metric("Active KEK Version", f"v{crypto_status.get('key_version', 1)}")

        st.markdown(f"""
        <div class="cv-card" style="margin-top: 16px;">
            <p><strong>Total Encrypted Objects:</strong> {crypto_status.get('encrypted_objects_count', 0)}</p>
            <p><strong>Encryption Ratio:</strong> {crypto_status.get('encryption_ratio_percent', 100.0)}%</p>
            <p><strong>Salt Provisioned:</strong> {'Yes' if crypto_status.get('user_has_salt') else 'Pending'}</p>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("Key Encryption Key (KEK) Rotation")
        st.markdown("<p style='color: #94a3b8;'>Rotate your master Key Encryption Key. Increments the user KEK version without invalidating historical backups (which retain per-object key version references).</p>", unsafe_allow_html=True)
        if st.button("🔄 Rotate Key Encryption Key Now", type="primary"):
            try:
                rot_res = client.rotate_crypto_key(token)
                st.success(f"Key rotated successfully! New KEK version: {rot_res.get('new_key_version')}")
                st.rerun()
            except Exception as e:
                st.error(f"Key rotation failed: {str(e)}")

    # -------------------------------------------------------------
    # TAB 4: Multi-Factor Authentication (MFA)
    # -------------------------------------------------------------
    with sec_tab4:
        st.subheader("RFC 6238 TOTP Multi-Factor Authentication")
        user = client.get_me(token)
        mfa_active = user.get("mfa_enabled", False)

        if mfa_active:
            st.markdown("""
            <div style="background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.3); padding: 16px; border-radius: 8px; margin-bottom: 20px;">
                <h3 style="color: #4ade80; margin: 0 0 8px 0;">🔒 Multi-Factor Authentication is ACTIVE</h3>
                <p style="color: #cbd5e1; margin: 0;">Your account is protected with a time-based one-time password (TOTP). MFA will be requested whenever you sign in.</p>
            </div>
            """, unsafe_allow_html=True)

            with st.expander("Disable Multi-Factor Authentication"):
                st.warning("Disabling MFA lowers your account security.")
                with st.form("disable_mfa_form"):
                    dis_pass = st.text_input("Enter your password:", type="password")
                    dis_code = st.text_input("Enter current 6-digit TOTP code:")
                    dis_submit = st.form_submit_button("Disable MFA", type="primary")

                    if dis_submit:
                        try:
                            client.disable_mfa(token, password=dis_pass, code=dis_code)
                            st.success("MFA disabled successfully.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error disabling MFA: {str(e)}")
        else:
            st.info("MFA is currently disabled on your account. Protect your backups by pairing Google Authenticator, Authy, or 1Password.")
            if "mfa_setup_secret" not in st.session_state:
                if st.button("Begin MFA Enrollment", type="primary"):
                    try:
                        setup_res = client.setup_mfa(token)
                        st.session_state["mfa_setup_secret"] = setup_res.get("secret")
                        st.session_state["mfa_setup_uri"] = setup_res.get("uri")
                        st.rerun()
                    except Exception as e:
                        st.error(f"MFA setup failed: {str(e)}")
            else:
                st.markdown(f"**Manual Entry Secret Key:** `{st.session_state['mfa_setup_secret']}`")
                st.code(st.session_state.get("mfa_setup_uri", ""), language="text")

                with st.form("confirm_mfa_form"):
                    code_verify = st.text_input("Enter the 6-digit code from your authenticator app:")
                    mfa_sub = st.form_submit_button("Confirm & Activate MFA", type="primary")

                    if mfa_sub:
                        try:
                            client.enable_mfa(token, secret=st.session_state["mfa_setup_secret"], code=code_verify.strip())
                            del st.session_state["mfa_setup_secret"]
                            if "mfa_setup_uri" in st.session_state:
                                del st.session_state["mfa_setup_uri"]
                            st.success("🎉 Multi-Factor Authentication enabled successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Verification failed: {str(e)}")
