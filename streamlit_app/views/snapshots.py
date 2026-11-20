import streamlit as st
import pandas as pd
from streamlit_app.api_client import CloudVaultClient, APIError
from streamlit_app.session import get_token, navigate_to
from streamlit_app.styles import format_bytes

def render_snapshots(client: CloudVaultClient):
    token = get_token()
    if not token:
        st.warning("Please sign in.")
        navigate_to("Login")
        return

    st.markdown("<h2 style='color: #38bdf8;'>📸 Snapshot Registry & Version History</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8;'>Browse immutable point-in-time snapshots, inspect protected file trees, and view cryptographic hashes.</p>", unsafe_allow_html=True)

    try:
        snapshots = client.list_snapshots(token)
    except Exception as e:
        st.error(f"Failed to fetch snapshots: {str(e)}")
        snapshots = []

    if not snapshots:
        st.info("No snapshots found. Upload a file or execute a backup plan to generate recovery snapshots.")
        return

    # Snapshot selector
    snap_map = {s["id"]: f"{s.get('name', 'Snapshot')} — {s.get('created_at', '')[:19].replace('T', ' ')} ({s.get('total_files', 0)} files, {format_bytes(s.get('total_stored_bytes', 0))})" for s in snapshots}
    selected_snap_id = st.selectbox(
        "Select Snapshot to Inspect:",
        options=list(snap_map.keys()),
        format_func=lambda sid: snap_map[sid]
    )

    selected_snap = next((s for s in snapshots if s["id"] == selected_snap_id), None)

    if selected_snap:
        # Snapshot Overview Card
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Files", f"{selected_snap.get('total_files', 0):,}")
        with c2:
            st.metric("Stored Size", format_bytes(selected_snap.get('total_stored_bytes', 0)))
        with c3:
            st.metric("Uncompressed", format_bytes(selected_snap.get('total_uncompressed_bytes', 0)))
        with c4:
            worm_active = selected_snap.get("worm_locked_until") is not None
            st.markdown(f"""
            <div style="padding-top: 10px;">
                <span class="badge {'badge-success' if not selected_snap.get('is_quarantined') else 'badge-danger'}">
                    {'QUARANTINED' if selected_snap.get('is_quarantined') else 'HEALTHY'}
                </span>
                <span class="badge badge-info" style="margin-top: 4px;">
                    {'WORM LOCKED' if worm_active else 'WORM PROTECTED'}
                </span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)

        # File Tree Table
        st.subheader("📂 Files in this Snapshot")
        with st.spinner("Loading file tree..."):
            try:
                tree = client.get_snapshot_tree(token, selected_snap_id)
            except Exception as e:
                st.error(f"Failed to load snapshot file tree: {str(e)}")
                tree = []

        if tree:
            table_rows = []
            for item in tree:
                table_rows.append({
                    "Path": item.get("relative_path"),
                    "Size": format_bytes(item.get("file_size")),
                    "SHA-256": (item.get("sha256_hash") or "")[:16] + "...",
                    "Modified": item.get("modified_at", "")[:19].replace("T", " "),
                    "Status": "Deleted" if item.get("is_deleted") else "Active"
                })
            st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

            # Quick Restore Section
            st.markdown("### 📥 Quick Restore From This Snapshot")
            file_options = {item["id"]: f"{item.get('relative_path')} ({format_bytes(item.get('file_size'))})" for item in tree}
            chosen_file_id = st.selectbox(
                "Choose file to restore:",
                options=list(file_options.keys()),
                format_func=lambda fid: file_options[fid]
            )
            dest_dir = st.text_input("Destination Directory on Server:", value="restored/documents")
            strat = st.selectbox("Conflict Strategy:", ["keep_both", "overwrite", "skip"])

            if st.button("🚀 Restore Selected File", type="primary"):
                try:
                    res = client.restore_file(
                        token=token,
                        snapshot_file_id=chosen_file_id,
                        destination_directory=dest_dir,
                        conflict_strategy=strat
                    )
                    st.success(f"Restored! Path: {res.get('destination')}. Verified SHA-256 integrity.")
                except APIError as e:
                    st.error(f"Restore failed: {e.detail}")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.info("No files found in this snapshot.")
