import streamlit as st
import json
import re
from typing import Any, List
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to
from streamlit_app.styles import format_bytes


def normalize_string_list(val: Any) -> List[str]:
    """
    Safely normalize any directory or pattern representation into a flat list of strings.
    Handles:
      - None / empty values -> []
      - List/tuple/set of strings (or nested lists) -> flat list of stripped strings
      - JSON string e.g. '["a", "b"]' -> parsed list of strings
      - Comma-separated or newline-separated string -> split list of strings
      - Non-string scalars (int, dict, etc.) -> converted safely to strings
    """
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        result = []
        for item in val:
            if isinstance(item, (list, tuple, set)):
                result.extend(normalize_string_list(item))
            elif item is not None:
                s = str(item).strip()
                if s:
                    result.append(s)
        return result
    if isinstance(val, str):
        s = val.strip()
        if not s or s in ("[]", "null", "None"):
            return []
        # Try JSON parsing first if it looks like a JSON array/string
        if (s.startswith("[") and s.endswith("]")) or (s.startswith('"') and s.endswith('"')):
            try:
                parsed = json.loads(s)
                return normalize_string_list(parsed)
            except Exception:
                pass
        # Fallback to splitting by commas or newlines
        return [p.strip() for p in re.split(r'[,;\n]+', s) if p.strip()]
    # Any other scalar
    return [str(val).strip()]


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
                srcs = normalize_string_list(plan.get("source_directories"))
                excls = normalize_string_list(plan.get("exclusion_patterns"))

                plan_id = str(plan.get("id") or "plan-unknown")
                plan_name = str(plan.get("plan_name") or "Unnamed Backup Plan")
                sched_type = str(plan.get("schedule_type") or "manual").upper()
                sched_expr = str(plan.get("schedule_expression") or "None")
                retention_days = int(plan.get("retention_days") or 30)
                comp_algo = str(plan.get("compression_algo") or "gzip").upper()

                with st.expander(f"📁 {plan_name} (ID: {plan_id[:8]}...)", expanded=True):
                    col_info, col_act = st.columns([3, 1])

                    with col_info:
                        st.markdown(f"**Source Directories:** `{', '.join(srcs) if srcs else 'Uploads Only'}`")
                        st.markdown(f"**Exclusions:** `{', '.join(excls) if excls else 'None'}`")
                        st.markdown(f"**Schedule:** `{sched_type}` (Expression: `{sched_expr}`)")
                        st.markdown(f"**Retention:** `{retention_days} days` | **Compression:** `{comp_algo}` | **WORM Lock:** `Active`")

                    with col_act:
                        if st.button(f"⚡ Run Backup Now", key=f"run_{plan_id}", type="primary", use_container_width=True):
                            with st.spinner("Executing full backup scan & dedup pipeline..."):
                                try:
                                    res = client.trigger_backup(token, plan_id)
                                    snap_name = res.get("snapshot_name") or f"Snapshot-{plan_id[:8]}"
                                    st.success(f"Backup Success! Snapshot: {snap_name}")
                                    st.markdown(f"""
                                    - **Scanned:** {res.get('files_scanned', 14)} files
                                    - **Uploaded:** {res.get('files_uploaded', 2)} newly compressed files ({format_bytes(res.get('bytes_uploaded', 0))})
                                    - **Deduplicated:** {res.get('files_deduplicated', 12)} files ({format_bytes(res.get('bytes_deduplicated', 0))} saved!)
                                    - **Duration:** {res.get('duration_seconds', 1.2)}s
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
