import streamlit as st
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to

def render_ai_assistant(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>🤖 CloudVault AI Disaster Recovery Copilot</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Ask questions about your disaster readiness, analyze backup trends, receive recovery recommendations, or execute approved automated recovery drills.</p>", unsafe_allow_html=True)

    # Prompt Suggestion Chips
    st.markdown("**Suggested Queries:**")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("📊 Evaluate DR readiness & RPO/RTO", use_container_width=True):
            st.session_state["pending_ai_query"] = "Evaluate my disaster recovery readiness and RPO/RTO metrics."
    with c2:
        if st.button("🛡️ Check security alerts & threats", use_container_width=True):
            st.session_state["pending_ai_query"] = "What is my current security status and are there any active ransomware alerts?"
    with c3:
        if st.button("💡 Recommend backup schedule", use_container_width=True):
            st.session_state["pending_ai_query"] = "Recommend an optimal backup schedule and retention policy."

    st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)

    if "ai_messages" not in st.session_state or not isinstance(st.session_state["ai_messages"], list):
        st.session_state["ai_messages"] = [
            {"role": "assistant", "content": "👋 Hello! I am your CloudVault AI Disaster Recovery & Security Copilot. How can I help you today? You can ask me to evaluate DR readiness, check your RPO/RTO metrics, or analyze backup trends."}
        ]

    # Render Chat History
    for idx, msg in enumerate(st.session_state.get("ai_messages", [])):
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("action_card"):
                _render_action_card(msg["action_card"], client, token, card_index=idx)

    # Handle incoming input
    user_input = st.chat_input("Ask CloudVault Copilot anything...")
    if "pending_ai_query" in st.session_state and st.session_state["pending_ai_query"]:
        user_input = st.session_state.pop("pending_ai_query")

    if user_input:
        # Display user message
        st.session_state["ai_messages"].append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Query AI backend
        with st.chat_message("assistant"):
            with st.spinner("AI Copilot analyzing cluster telemetry..."):
                try:
                    res = client.query_ai_assistant(token, user_input)
                    reply_text = res.get("response", "Telemetry retrieved.")
                    st.markdown(reply_text)

                    act_card = res.get("action_card")
                    msg_obj = {"role": "assistant", "content": reply_text}
                    if act_card:
                        msg_obj["action_card"] = act_card
                        _render_action_card(act_card, client, token, card_index=len(st.session_state["ai_messages"]))

                    st.session_state["ai_messages"].append(msg_obj)
                except APIError as e:
                    err_msg = f"AI Error: {e.detail}"
                    st.error(err_msg)
                    st.session_state["ai_messages"].append({"role": "assistant", "content": err_msg})
                except Exception as e:
                    err_msg = f"Network Error: {str(e)}"
                    st.error(err_msg)
                    st.session_state["ai_messages"].append({"role": "assistant", "content": err_msg})


def _render_action_card(act_card: dict, client: CloudVaultClient, token: str, card_index: int = 0):
    """Render high-visibility HMAC confirmation card for privileged actions."""
    action_type = act_card.get("action_type", "PRIVILEGED_ACTION")
    conf_token = act_card.get("confirmation_token")
    description = act_card.get("description", "Requires confirmation.")

    st.markdown(f"""
    <div class="action-proposal-card">
        <h4 style="color: #f59e0b; margin: 0 0 6px 0;">⚡ Action Proposal: {action_type}</h4>
        <p style="color: #f8fafc; margin: 0 0 10px 0;">{description}</p>
        <span class="badge badge-warning">Cryptographic HMAC Verification Required</span>
    </div>
    """, unsafe_allow_html=True)

    if conf_token:
        btn_key = f"confirm_{card_index}_{conf_token[:10]}"
        if st.button(f"✅ Approve & Execute {action_type}", key=btn_key, type="primary"):
            with st.spinner("Verifying cryptographic token and executing operation..."):
                try:
                    exec_res = client.confirm_ai_action(token, conf_token)
                    st.success(f"Execution Succeeded! {exec_res.get('message', 'Action completed.')}")
                except Exception as e:
                    st.error(f"Action execution failed: {str(e)}")
