import streamlit as st
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import set_token, set_user, navigate_to

def render_register(client: CloudVaultClient):
    st.markdown("<h2 style='text-align: center; color: #38bdf8;'>✨ Create Your CloudVault Account</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #94a3b8;'>Secure, multi-tenant cloud backup with zero-trust envelope encryption.</p>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("register_form"):
            full_name = st.text_input("Full Name", placeholder="e.g. Alice Chen")
            email = st.text_input("Email Address", placeholder="alice@enterprise.com")
            password = st.text_input("Password", type="password", placeholder="At least 8 characters")
            confirm_password = st.text_input("Confirm Password", type="password", placeholder="Repeat password")

            # Password Strength Feedback
            if password:
                score = 0
                if len(password) >= 8: score += 1
                if any(c.isupper() for c in password): score += 1
                if any(c.islower() for c in password): score += 1
                if any(c.isdigit() for c in password): score += 1
                if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 1

                colors = ["#ef4444", "#f97316", "#eab308", "#38bdf8", "#22c55e"]
                labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
                st.caption(f"Password Strength: **{labels[score-1 if score > 0 else 0]}**")
                st.progress(score / 5.0)

            submitted = st.form_submit_button("🚀 Complete Registration", use_container_width=True, type="primary")

            if submitted:
                if not full_name.strip() or not email.strip() or not password:
                    st.error("Please fill in all required fields.")
                elif len(password) < 8:
                    st.error("Password must be at least 8 characters long.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    try:
                        res = client.register(email=email.strip(), password=password, full_name=full_name.strip())
                        token = res.get("access_token")
                        user = res.get("user")
                        if token and user:
                            set_token(token)
                            set_user(user)
                            st.success("🎉 Account created successfully! Redirecting to Dashboard...")
                            navigate_to("Dashboard")
                        else:
                            st.success("Registration successful! Please log in.")
                            navigate_to("Login")
                    except APIError as e:
                        st.error(f"Registration failed: {e.detail}")
                    except Exception as e:
                        st.error(f"Network error: {str(e)}")

        st.markdown("<p style='text-align: center; margin-top: 16px;'>Already have an account? </p>", unsafe_allow_html=True)
        if st.button("🔐 Sign In Instead", use_container_width=True):
            navigate_to("Login")
