import streamlit as st
import json
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to
from streamlit_app.styles import format_bytes

def render_backup_plans(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>📋 Backup Plans & Automation Policies</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Configure scheduled backup policies, retention schedules, and file exclusion rules.</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Active Plans", "➕ Create New Plan"])

    with tab1:
        try:
            plans = client.list_backup_plans(token)
        except Exception as e:
            st.error(f"Failed to load plans: {str(e)}")
            plans = []

        if not plans:
            st.info("No backup plans configured yet. Click 'Create New Plan' above to set one up.")
        else:
            for plan in plans:
                try:
                    srcs = json.loads(plan.get("source_directories", "[]"))
                except Exception:
                    srcs = [plan.get("source_directories", "")]

                try:
                    excls = json.loads(plan.get("exclusion_patterns", "[]"))
                except Exception:
                    excls = []

                with st.expander(f"📁 {plan.get('plan_name')} (ID: {plan.get('id')[:8]}...)", expanded=True):
                    col_info, col_act = st.columns([3, 1])

                    with col_info:
                        st.markdown(f"**Source Directories:** `{', '.join(srcs) if srcs else 'Uploads Only'}`")
                        st.markdown(f"**Exclusions:** `{', '.join(excls) if excls else 'None'}`")
                        st.markdown(f"**Schedule:** `{plan.get('schedule_type', 'manual').upper()}` (Expression: `{plan.get('schedule_expression') or 'None'}`)")
                        st.markdown(f"**Retention:** `{plan.get('retention_days', 30)} days` | **Compression:** `{plan.get('compression_algo', 'gzip').upper()}` | **WORM Lock:** `Active`")

                    with col_act:
                        if st.button(f"⚡ Run Backup Now", key=f"run_{plan['id']}", type="primary", use_container_width=True):
                            with st.spinner("Executing full backup scan & dedup pipeline..."):
                                try:
                                    res = client.trigger_backup(token, plan["id"])
                                    st.success(f"Backup Success! Snapshot: {res.get('snapshot_name')}")
                                    st.markdown(f"""
                                    - **Scanned:** {res.get('files_scanned')} files
                                    - **Uploaded:** {res.get('files_uploaded')} newly compressed files ({format_bytes(res.get('bytes_uploaded'))})
                                    - **Deduplicated:** {res.get('files_deduplicated')} files ({format_bytes(res.get('bytes_deduplicated'))} saved!)
                                    - **Duration:** {res.get('duration_seconds')}s
                                    """)
                                except APIError as e:
                                    st.error(f"Backup failed: {e.detail}")
                                except Exception as e:
                                    st.error(f"Error: {str(e)}")

    with tab2:
        st.subheader("Configure New Plan")
        with st.form("new_plan_form"):
            plan_name = st.text_input("Plan Name", placeholder="e.g. Daily Documents & Code")
            source_dirs = st.text_area("Source Directories (one per line or comma-separated)", placeholder="C:\\Users\\User\\Documents\nC:\\Projects")
            exclusions = st.text_input("Exclusion Patterns (comma-separated)", value="*.tmp, *.log, .git, node_modules, __pycache__")
            
            c1, c2 = st.columns(2)
            with c1:
                sched_type = st.selectbox("Schedule Type", ["manual", "interval", "cron"])
                retention = st.number_input("Retention Period (Days)", min_value=1, max_value=365, value=30)
            with c2:
                sched_expr = st.text_input("Schedule Expression (e.g. '0 2 * * *' for cron or '3600' for interval sec)", value="")
                comp_algo = st.selectbox("Compression Algorithm", ["gzip", "zlib", "bz2"])

            create_sub = st.form_submit_button("Save Backup Plan", type="primary", use_container_width=True)

            if create_sub:
                if not plan_name.strip():
                    st.error("Please enter a plan name.")
                else:
                    dirs_list = [d.strip() for d in source_dirs.replace("\n", ",").split(",") if d.strip()]
                    excl_list = [e.strip() for e in exclusions.split(",") if e.strip()]
                    if not dirs_list:
                        dirs_list = ["uploads/"]

                    try:
                        client.create_backup_plan(
                            token=token,
                            plan_name=plan_name.strip(),
                            source_directories=dirs_list,
                            exclusion_patterns=excl_list,
                            schedule_type=sched_type,
                            schedule_expression=sched_expr.strip() if sched_expr.strip() else None,
                            retention_days=int(retention),
                            compression_algo=comp_algo
                        )
                        st.success("Backup plan created successfully!")
                        st.rerun()
                    except APIError as e:
                        st.error(f"Failed to create plan: {e.detail}")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
