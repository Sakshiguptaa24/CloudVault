import os
import streamlit as st
from streamlit_app.api_client import CloudVaultClient
from streamlit_app.session import (
    init_session, get_token, get_user, is_authenticated, logout, navigate_to
)
from streamlit_app.styles import apply_custom_css
from streamlit_app.views.landing import render_landing
from streamlit_app.views.register import render_register
from streamlit_app.views.login import render_login
from streamlit_app.views.dashboard import render_dashboard
from streamlit_app.views.upload_backup import render_upload_backup
from streamlit_app.views.backup_plans import render_backup_plans
from streamlit_app.views.snapshots import render_snapshots
from streamlit_app.views.restore_recovery import render_restore_recovery
from streamlit_app.views.security_center import render_security_center
from streamlit_app.views.ai_assistant import render_ai_assistant
from streamlit_app.views.analytics import render_analytics
from streamlit_app.views.settings import render_settings

def main():
    st.set_page_config(
        page_title="CloudVault 2.0 – Cloud Backup & DR",
        page_icon="☁️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Apply dark cybersecurity styles
    apply_custom_css()

    # Initialize session state variables
    init_session()

    # Backend API client
    client = CloudVaultClient()

    # Sidebar Navigation
    with st.sidebar:
        st.markdown("""
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">
            <span style="font-size: 2rem;">☁️</span>
            <div>
                <h2 style="font-size: 1.3rem; margin: 0; color: #38bdf8; font-weight: 800;">CloudVault 2.0</h2>
                <span style="font-size: 0.75rem; color: #94a3b8;">Zero-Trust Disaster Recovery</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        user = get_user()
        if is_authenticated() and user:
            st.markdown(f"""
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px; margin-bottom: 20px;">
                <div style="font-size: 0.8rem; color: #94a3b8;">AUTHENTICATED AS</div>
                <div style="font-weight: 600; color: #f8fafc; font-size: 0.95rem;">{user.get('full_name')}</div>
                <div style="font-size: 0.75rem; color: #38bdf8;">{user.get('email')}</div>
            </div>
            """, unsafe_allow_html=True)

            nav_options = [
                ("🏠 Dashboard", "Dashboard"),
                ("📤 Upload & Backup", "Upload & Backup"),
                ("📋 Backup Plans", "Backup Plans"),
                ("📸 Snapshots & Files", "Snapshots"),
                ("🔄 Restore & Recovery", "Restore & Recovery"),
                ("🛡️ Security Center", "Security Center"),
                ("🤖 AI Copilot", "AI Assistant"),
                ("📈 Analytics & Forecast", "Analytics"),
                ("⚙️ Multi-Cloud & Settings", "Settings"),
                ("🌐 Overview & Specs", "Landing")
            ]
        else:
            nav_options = [
                ("🌐 Overview & Specs", "Landing"),
                ("🔐 Sign In", "Login"),
                ("✨ Create Account", "Register")
            ]

        # Navigation Buttons
        current_page = st.session_state.get("current_page", "Landing")
        for label, page_key in nav_options:
            is_active = (current_page == page_key)
            btn_type = "primary" if is_active else "secondary"
            if st.button(label, key=f"nav_{page_key}", use_container_width=True, type=btn_type):
                navigate_to(page_key)

        st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)

        # Status & Logout
        if is_authenticated():
            if st.button("🚪 Sign Out", use_container_width=True):
                logout()
        else:
            st.markdown("""
            <div style="text-align: center; color: #64748b; font-size: 0.8rem;">
                Multi-User Tenant Isolation<br>
                PostgreSQL & SQLite Engine
            </div>
            """, unsafe_allow_html=True)

    # Route Page
    page = st.session_state.get("current_page", "Landing")

    # Protection Guard for Private Views
    protected_pages = [
        "Dashboard", "Upload & Backup", "Backup Plans", "Snapshots",
        "Restore & Recovery", "Security Center", "AI Assistant",
        "Analytics", "Settings"
    ]

    if page in protected_pages and not is_authenticated():
        st.warning("🔒 Authentication required to access this resource.")
        render_login(client)
        return

    # Render Active Page
    if page == "Landing":
        render_landing(client)
    elif page == "Register":
        render_register(client)
    elif page == "Login":
        render_login(client)
    elif page == "Dashboard":
        render_dashboard(client)
    elif page == "Upload & Backup":
        render_upload_backup(client)
    elif page == "Backup Plans":
        render_backup_plans(client)
    elif page == "Snapshots":
        render_snapshots(client)
    elif page == "Restore & Recovery":
        render_restore_recovery(client)
    elif page == "Security Center":
        render_security_center(client)
    elif page == "AI Assistant":
        render_ai_assistant(client)
    elif page == "Analytics":
        render_analytics(client)
    elif page == "Settings":
        render_settings(client)
    else:
        render_landing(client)

if __name__ == "__main__":
    main()
