import streamlit as st
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import set_token, set_user, navigate_to

def render_login(client: CloudVaultClient):
    st.markdown("<h2 style='text-align: center; color: #38bdf8;'>🔐 Sign In to CloudVault</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #94a3b8;'>Enter your credentials to access your protected snapshots and disaster recovery center.</p>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        mfa_required = st.session_state.get("login_mfa_required", False)

        if not mfa_required:
            with st.form("login_form"):
                email = st.text_input("Email Address", placeholder="user@enterprise.com", value=st.session_state.get("temp_login_email", ""))
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

                if submitted:
                    if not email.strip() or not password:
                        st.error("Please enter both email and password.")
                    else:
                        try:
                            res = client.login(email=email.strip(), password=password)
                            if res.get("mfa_required"):
                                st.session_state["login_mfa_required"] = True
                                st.session_state["temp_login_email"] = email.strip()
                                st.session_state["temp_login_password"] = password
                                st.rerun()
                            else:
                                token = res.get("access_token")
                                user = res.get("user")
                                set_token(token)
                                set_user(user)
                                st.success("Authentication successful! Loading dashboard...")
                                navigate_to("Dashboard")
                        except APIError as e:
                            st.error(f"Login failed: {e.detail}")
                        except Exception as e:
                            st.error(f"Connection error: {str(e)}")

            st.markdown("<p style='text-align: center; margin-top: 16px;'>Need an account?</p>", unsafe_allow_html=True)
            if st.button("✨ Create New Account", use_container_width=True):
                navigate_to("Register")

        else:
            # Multi-Factor Authentication Challenge
            st.warning("🔒 Multi-Factor Authentication Required")
            st.info(f"Authenticating as: **{st.session_state.get('temp_login_email')}**")

            with st.form("mfa_challenge_form"):
                mfa_code = st.text_input("MFA Code", placeholder="6-digit TOTP or 8-char recovery code")
                c1, c2 = st.columns(2)
                with c1:
                    submit_mfa = st.form_submit_button("Verify MFA", use_container_width=True, type="primary")
                with c2:
                    cancel_mfa = st.form_submit_button("Cancel", use_container_width=True)

                if cancel_mfa:
                    st.session_state["login_mfa_required"] = False
                    st.session_state["temp_login_password"] = ""
                    st.rerun()

                if submit_mfa:
                    if not mfa_code.strip():
                        st.error("Please enter your verification code.")
                    else:
                        try:
                            res = client.login(
                                email=st.session_state.get("temp_login_email"),
                                password=st.session_state.get("temp_login_password"),
                                mfa_code=mfa_code.strip()
                            )
                            token = res.get("access_token")
                            user = res.get("user")
                            set_token(token)
                            set_user(user)
                            st.session_state["login_mfa_required"] = False
                            st.session_state["temp_login_email"] = ""
                            st.session_state["temp_login_password"] = ""
                            st.success("MFA verified! Loading dashboard...")
                            navigate_to("Dashboard")
                        except APIError as e:
                            st.error(f"MFA verification failed: {e.detail}")
                        except Exception as e:
                            st.error(f"Error: {str(e)}")
