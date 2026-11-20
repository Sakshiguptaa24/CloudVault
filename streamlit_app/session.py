import streamlit as st
from typing import Optional, Dict, Any

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
    st.rerun()


def navigate_to(page_name: str):
    st.session_state["current_page"] = page_name
    st.rerun()
