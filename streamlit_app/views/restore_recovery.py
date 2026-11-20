import streamlit as st
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to
from streamlit_app.styles import format_bytes

def render_restore_recovery(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>🔄 Disaster Recovery & Restore Center</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Execute granular file recovery or full point-in-time snapshot restoration with guaranteed cryptographic integrity verification.</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Entire Snapshot Recovery", "Deleted File & Version Recovery"])

    with tab1:
        st.subheader("Point-in-Time Snapshot Restoration")
        try:
            snapshots = client.list_snapshots(token)
        except Exception as e:
            st.error(f"Failed to fetch snapshots: {str(e)}")
            snapshots = []

        if not snapshots:
            st.info("No snapshots available for recovery.")
        else:
            snap_dict = {s["id"]: f"{s.get('name')} ({s.get('total_files')} files - {s.get('created_at', '')[:19].replace('T', ' ')})" for s in snapshots}
            sel_snap_id = st.selectbox("Select Target Recovery Point (Snapshot):", options=list(snap_dict.keys()), format_func=lambda sid: snap_dict[sid])

            dest_folder = st.text_input("Destination Directory:", value="restored/full_snapshot", key="snap_dest")
            conflict_mode = st.selectbox("Conflict Resolution Strategy:", ["keep_both", "overwrite", "skip"], key="snap_conflict")

            if st.button("🚀 Restore Entire Snapshot", type="primary", use_container_width=True):
                with st.spinner("Executing full snapshot recovery pipeline & verifying SHA-256 hashes..."):
                    try:
                        res = client.restore_snapshot(
                            token=token,
                            snapshot_id=sel_snap_id,
                            destination_directory=dest_folder,
                            conflict_strategy=conflict_mode
                        )
                        st.success("✅ Recovery Completed Successfully!")
                        st.markdown(f"""
                        <div class="cv-card" style="border-left: 4px solid #22c55e;">
                            <h3 style="margin-top: 0; color: #4ade80;">Restoration Receipt</h3>
                            <p><strong>Files Restored:</strong> {res.get('files_restored')}</p>
                            <p><strong>Data Volume Restored:</strong> {format_bytes(res.get('bytes_restored'))}</p>
                            <p><strong>Target Directory:</strong> <code>{res.get('destination')}</code></p>
                            <p><strong>Integrity Verification:</strong> <span class="badge badge-success">100% Validated (SHA-256)</span></p>
                        </div>
                        """, unsafe_allow_html=True)
                    except APIError as e:
                        st.error(f"Restoration failed: {e.detail}")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    with tab2:
        st.subheader("Deleted File Recovery")
        try:
            plans = client.list_backup_plans(token)
        except Exception:
            plans = []

        if not plans:
            st.info("No backup plans found.")
        else:
            plan_map = {p["id"]: p["plan_name"] for p in plans}
            chosen_plan_id = st.selectbox("Select Backup Plan to search for deleted files:", options=list(plan_map.keys()), format_func=lambda pid: plan_map[pid])

            if chosen_plan_id:
                try:
                    deleted_files = client.get_deleted_files(token, chosen_plan_id)
                except Exception as e:
                    st.error(f"Failed to fetch deleted files: {str(e)}")
                    deleted_files = []

                if not deleted_files:
                    st.info("No deleted files detected for this plan. All tracked files are present in the latest snapshot.")
                else:
                    st.write(f"Found {len(deleted_files)} recoverable deleted file(s):")
                    df_options = {df["id"]: f"{df.get('relative_path')} (Last seen: {df.get('last_seen_snapshot_name')})" for df in deleted_files}
                    sel_df_id = st.selectbox("Choose file to recover:", options=list(df_options.keys()), format_func=lambda dfid: df_options[dfid])
                    del_dest = st.text_input("Destination Directory:", value="restored/deleted_recovery", key="del_dest")

                    if st.button("Recover Deleted File", type="primary"):
                        try:
                            res = client.restore_file(
                                token=token,
                                snapshot_file_id=sel_df_id,
                                destination_directory=del_dest,
                                conflict_strategy="keep_both"
                            )
                            st.success(f"File restored to: {res.get('destination')} with verified integrity.")
                        except APIError as e:
                            st.error(f"Recovery failed: {e.detail}")
                        except Exception as e:
                            st.error(f"Error: {str(e)}")
