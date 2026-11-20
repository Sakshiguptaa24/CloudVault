import streamlit as st
from typing import Optional, Dict, Any

def init_demo_user():
    """Ensure an active demonstration user profile is loaded for public visitors in demo mode."""
    from streamlit_app.demo_service import is_demo_mode
    if is_demo_mode():
        if not st.session_state.get("user") or not st.session_state.get("access_token"):
            st.session_state["user"] = {
                "id": "demo-evaluator-001",
                "full_name": "Demo Evaluator",
                "email": "demo-evaluator@cloudvault.internal",
                "role": "evaluator",
                "is_demo_mode": True
            }
            st.session_state["access_token"] = "demo-session-token-2026"


def init_session():
    """Ensure all required session state variables exist with safe defaults."""
    if "access_token" not in st.session_state:
        st.session_state["access_token"] = None
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Landing"
    if "login_mfa_required" not in st.session_state:
        st.session_state["login_mfa_required"] = False
    if "temp_login_email" not in st.session_state:
        st.session_state["temp_login_email"] = ""
    if "temp_login_password" not in st.session_state:
        st.session_state["temp_login_password"] = ""
    if "ai_messages" not in st.session_state:
        st.session_state["ai_messages"] = [
            {"role": "assistant", "content": "👋 Hello! I am your CloudVault AI Disaster Recovery & Security Copilot. How can I help you today? You can ask me to evaluate DR readiness, check your RPO/RTO metrics, or analyze backup trends."}
        ]
    if "pending_action_card" not in st.session_state:
        st.session_state["pending_action_card"] = None

    # Load demo guest credentials if operating in demo mode
    init_demo_user()


def get_token() -> Optional[str]:
    return st.session_state.get("access_token")


def set_token(token: str):
    st.session_state["access_token"] = token


def get_user() -> Optional[Dict[str, Any]]:
    return st.session_state.get("user")


def set_user(user: Dict[str, Any]):
    st.session_state["user"] = user


def is_authenticated() -> bool:
    return bool(st.session_state.get("access_token") and st.session_state.get("user"))


def logout():
    """Completely wipe user credentials and session variables."""
    st.session_state["access_token"] = None
    st.session_state["user"] = None
    st.session_state["current_page"] = "Landing"
    st.session_state["login_mfa_required"] = False
    st.session_state["temp_login_email"] = ""
    st.session_state["temp_login_password"] = ""
    st.session_state["ai_messages"] = [
        {"role": "assistant", "content": "👋 Hello! I am your CloudVault AI Disaster Recovery & Security Copilot. How can I help you today?"}
    ]
    st.session_state["pending_action_card"] = None
    st.session_state["auth_expired_message"] = None
    st.rerun()


def handle_auth_expired(message: str = "Your session has expired. Please sign in again."):
    """
    Clear credentials, set an expiration flash notice, and navigate to Login.
    Guarded against infinite redirect loops if already on the Login page.
    """
    st.session_state["access_token"] = None
    st.session_state["user"] = None
    st.session_state["login_mfa_required"] = False
    st.session_state["temp_login_email"] = ""
    st.session_state["temp_login_password"] = ""
    st.session_state["pending_action_card"] = None
    st.session_state["auth_expired_message"] = message
    if st.session_state.get("current_page") != "Login":
        st.session_state["current_page"] = "Login"
        st.rerun()


def navigate_to(page_name: str):
    st.session_state["current_page"] = page_name
    st.rerun()
