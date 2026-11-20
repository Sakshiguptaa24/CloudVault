import streamlit as st
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, logout, navigate_to
from streamlit_app.styles import format_bytes

def render_settings(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>⚙️ Multi-Cloud & Account Settings</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Manage multi-cloud storage routing, review tenant profile, and inspect recovery codes.</p>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["🌐 Multi-Cloud Storage Routing", "👤 User Profile & Quotas", "🔑 Emergency Recovery Codes"])

    # -------------------------------------------------------------
    # TAB 1: Multi-Cloud Storage Routing
    # -------------------------------------------------------------
    with tab1:
        st.subheader("Multi-Cloud Engine Topology")
        try:
            inv = client.get_storage_inventory(token)
            matrix = client.get_providers_matrix(token)
        except Exception:
            inv = {"primary_provider": "mock", "secondary_provider": "s3", "failover_enabled": True}
            matrix = {"compliance_support": {}}

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Primary Storage Provider", inv.get("primary_provider", "MOCK").upper())
        with c2:
            st.metric("Secondary Failover", inv.get("secondary_provider", "S3").upper())
        with c3:
            st.metric("Failover Automation", "ENABLED" if inv.get("failover_enabled") else "DISABLED")

        st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)

        st.subheader("Storage Compliance & Capability Matrix")
        st.markdown("""
        | Provider | WORM Retention | AES-256-GCM Envelope | Streaming Chunks | Failover Ready |
        | :--- | :---: | :---: | :---: | :---: |
        | **Local Mock Engine** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
        | **Google Cloud Storage (GCS)** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
        | **Amazon Web Services (S3)** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
        | **Microsoft Azure Blob** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
        """)

    # -------------------------------------------------------------
    # TAB 2: User Profile
    # -------------------------------------------------------------
    with tab2:
        st.subheader("Account Details")
        user = client.get_me(token)

        st.markdown(f"""
        <div class="cv-card">
            <p><strong>Full Name:</strong> {user.get('full_name')}</p>
            <p><strong>Email Address:</strong> {user.get('email')}</p>
            <p><strong>User ID (Tenant GUID):</strong> <code>{user.get('id')}</code></p>
            <p><strong>Role:</strong> <span class="badge badge-info">{user.get('role', 'user').upper()}</span></p>
            <p><strong>Storage Quota:</strong> {format_bytes(user.get('quota_bytes', 5368709120))}</p>
            <p><strong>Current Consumption:</strong> {format_bytes(user.get('used_bytes', 0))}</p>
            <p><strong>Account Created:</strong> {user.get('created_at', '')[:19].replace('T', ' ')}</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚪 Sign Out of CloudVault", type="primary"):
            logout()

    # -------------------------------------------------------------
    # TAB 3: Emergency Recovery Codes
    # -------------------------------------------------------------
    with tab3:
        st.subheader("Emergency Account Recovery Codes")
        st.markdown("<p style='color: #94a3b8;'>One-time backup codes can be used to authenticate if you ever lose access to your TOTP authenticator device.</p>", unsafe_allow_html=True)

        if st.button("Generate / View Recovery Codes"):
            try:
                rec_res = client.get_recovery_codes(token)
                codes = rec_res.get("recovery_codes", [])
                if codes:
                    st.success(f"Generated {len(codes)} one-time recovery codes. Store these in a secure password manager:")
                    st.code("\n".join(codes), language="text")
                else:
                    st.info("No active recovery codes found. Please enable MFA first.")
            except Exception as e:
                st.error(f"Error fetching codes: {str(e)}")
