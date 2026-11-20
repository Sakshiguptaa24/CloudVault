import sys
import os
import argparse
import json
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = True):
    """Start CloudVault FastAPI server."""
    import uvicorn
    import socket
    
    lan_ip = "localhost"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            lan_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            lan_ip = "127.0.0.1"

    print(f"\n=======================================================")
    print(f"  ☁️  CloudVault – Cloud Backup & Recovery System")
    print(f"=======================================================")
    print(f"  💻 Laptop (Localhost):  http://localhost:{port}")
    print(f"  📱 Multiple Devices:    http://{lan_ip}:{port} (Same Wi-Fi/LAN)")
    print(f"  📖 API Docs (Swagger):  http://localhost:{port}/docs")
    print(f"  🔒 Storage Mode:        {os.environ.get('STORAGE_PROVIDER', 'mock').upper()}")
    print(f"=======================================================\n")
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=reload)

def run_tests():
    """Run full automated pytest test suite."""
    import pytest
    print("\nRunning CloudVault Test Suite...")
    exit_code = pytest.main(["backend/tests", "-v"])
    sys.exit(exit_code)

def run_cli_backup(folder_path: str, plan_name: str = None):
    """Perform a backup directly from the terminal."""
    from backend.app.database import SessionLocal, Base, engine
    from backend.app.models import User, BackupPlan
    from backend.app.storage import get_storage_provider
    from backend.app.services.backup_service import execute_backup_plan

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    storage = get_storage_provider()

    try:
        user = db.query(User).first()
        if not user:
            print("No users found. Please create a user via the Web UI or register first.")
            return

        target_dir = Path(folder_path).resolve()
        if not target_dir.exists():
            print(f"Error: Target directory does not exist: {target_dir}")
            return

        name = plan_name or f"CLI Backup ({target_dir.name})"
        plan = db.query(BackupPlan).filter(
            BackupPlan.user_id == user.id,
            BackupPlan.plan_name == name
        ).first()

        if not plan:
            plan = BackupPlan(
                user_id=user.id,
                plan_name=name,
                source_directories=json.dumps([str(target_dir)]),
                exclusion_patterns=json.dumps(["*.tmp", ".git", "node_modules"]),
                schedule_type="manual"
            )
            db.add(plan)
            db.commit()
            db.refresh(plan)

        print(f"\nScanning and backing up: {target_dir}")
        snap, job = execute_backup_plan(plan.id, user, db, storage, trigger_type="CLI")

        print("\n================ BACKUP SUMMARY ================")
        print(f"  Snapshot:        {snap.name}")
        print(f"  Files Scanned:   {job.files_scanned}")
        print(f"  Files Uploaded:  {job.files_uploaded} (Newly compressed)")
        print(f"  Files Deduped:   {job.files_deduplicated} (0-byte cloud transfer)")
        print(f"  Bytes Uploaded:  {job.bytes_uploaded} bytes")
        print(f"  Bytes Deduped:   {job.bytes_deduplicated} bytes")
        print(f"  Status:          {job.status}")
        print(f"  Duration:        {job.duration_seconds}s")
        print("================================================\n")
    finally:
        db.close()

def run_cli_dr_drill():
    """Execute synthetic disaster recovery drill from CLI."""
    from backend.app.database import SessionLocal, Base, engine
    from backend.app.models import User
    from backend.app.storage import get_storage_provider
    from backend.app.services.dr_service import run_synthetic_recovery_drill, get_dr_metrics

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    storage = get_storage_provider()
    try:
        user = db.query(User).first()
        if not user:
            print("No users found. Please create a user via the Web UI or register first.")
            return
        print("\nInitiating Sandboxed Synthetic Recovery Drill...")
        try:
            res = run_synthetic_recovery_drill(None, user.id, db, storage)
        except ValueError as ve:
            print(f"Notice: {str(ve)} Please execute a backup first (e.g. 'python cli.py backup <folder>').")
            return
        print("\n============= DISASTER RECOVERY DRILL =============")
        print(f"  Status:            {res['status']}")
        print(f"  Snapshot:          {res['snapshot_name']}")
        print(f"  Files Tested:      {res['files_tested']}")
        print(f"  Data Verified:     {res['bytes_tested']} bytes (100% SHA-256 match)")
        print(f"  Duration:          {res['duration_seconds']}s")
        print(f"  Throughput:        {res['restoration_speed_mbps']} MB/s")
        print(f"  Calculated RPO:    {res['rpo_hours']}h")
        print(f"  Estimated RTO:     {res['estimated_rto_minutes']} min")
        print("===================================================\n")
    finally:
        db.close()

def run_cli_security_scan(folder_path: str):
    """Run Shannon entropy and ransomware scan on a directory."""
    from backend.app.services.ransomware_service import analyze_directory_for_ransomware
    target = Path(folder_path).resolve()
    if not target.exists():
        print(f"Directory not found: {target}")
        return
    print(f"\nAnalyzing directory for ransomware and anomalous entropy: {target}")
    result = analyze_directory_for_ransomware(str(target))
    print("\n============== SECURITY & ENTROPY SCAN ==============")
    print(f"  Risk Score:        {result['risk_score']} / 100")
    print(f"  Threat Level:      {result['alert_level']}")
    print(f"  Files Scanned:     {result['files_scanned']}")
    print(f"  Suspicious Files:  {result['suspicious_count']}")
    print(f"  Average Entropy:   {result['average_entropy']} bits/byte")
    print(f"  Matched Ransomware:{result['matched_extensions']}")
    print(f"  Action Taken:      {result['action_taken']}")
    print("=====================================================\n")

def run_cli_health():
    """Print CloudVault 2.0 Backup Health Score and Analytics."""
    from backend.app.database import SessionLocal, Base, engine
    from backend.app.models import User
    from backend.app.services.analytics_service import calculate_backup_health_score, get_analytics_overview

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user = db.query(User).first()
        if not user:
            print("No users found.")
            return
        health = calculate_backup_health_score(user.id, db)
        overview = get_analytics_overview(user.id, db)
        print("\n============= CLOUDVAULT 2.0 HEALTH SCORE =============")
        print(f"  Overall Score:     {health['health_score']} / 100 ({health['rating']})")
        print(f"  Breakdown:         RPO: {health['breakdown']['rpo_score']}/35 | Reliability: {health['breakdown']['job_reliability_score']}/30")
        print(f"                     Security: {health['breakdown']['security_posture_score']}/20 | Dedup: {health['breakdown']['dedup_efficiency_score']}/15")
        print(f"  Dedup Ratio:       {overview['deduplication']['ratio_multiplier']}x ({overview['deduplication']['space_saved_percentage']}% saved)")
        print(f"  Est. Cloud Cost:   ${overview['cost_estimation']['estimated_monthly_cost_usd']}/month")
        print(f"  Recommendations:   {health['recommendations']}")
        print("=======================================================\n")
    finally:
        db.close()

def run_streamlit(port: int = 8501):
    """Launch the Streamlit multi-user application."""
    import subprocess
    print(f"\n=======================================================")
    print(f"  ☁️  CloudVault 2.0 – Streamlit Multi-User Web Client")
    print(f"=======================================================")
    print(f"  🌐 Streamlit Local:    http://localhost:{port}")
    print(f"  🔒 Session Isolation: Active (Strict per-session JWT)")
    print(f"=======================================================\n")
    cmd = [sys.executable, "-m", "streamlit", "run", "streamlit_app.py", "--server.port", str(port)]
    subprocess.run(cmd)

def main():
    parser = argparse.ArgumentParser(description="CloudVault 2.0 CLI Controller")
    subparsers = parser.add_subparsers(dest="command")

    # Server
    serve_parser = subparsers.add_parser("serve", help="Run the FastAPI API server")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to run server on")
    serve_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface")

    # Streamlit UI
    ui_parser = subparsers.add_parser("ui", help="Run Streamlit Multi-User Web UI")
    ui_parser.add_argument("--port", type=int, default=8501, help="Port for Streamlit")
    st_parser = subparsers.add_parser("streamlit", help="Run Streamlit Multi-User Web UI")
    st_parser.add_argument("--port", type=int, default=8501, help="Port for Streamlit")

    # Tests
    subparsers.add_parser("test", help="Run all unit and integration tests")

    # Backup
    backup_parser = subparsers.add_parser("backup", help="Run backup on a local folder")
    backup_parser.add_argument("folder", type=str, help="Path to local folder to backup")
    backup_parser.add_argument("--name", type=str, default=None, help="Name of backup plan")

    # DR Drill
    subparsers.add_parser("dr", help="Run synthetic disaster recovery drill")

    # Security Scan
    sec_parser = subparsers.add_parser("security-scan", help="Scan folder for ransomware / high entropy")
    sec_parser.add_argument("folder", type=str, help="Directory to inspect")

    # Health
    subparsers.add_parser("health", help="Check CloudVault 2.0 health score and analytics")

    args = parser.parse_args()

    if args.command == "serve" or args.command is None:
        port = getattr(args, "port", 8000)
        host = getattr(args, "host", "0.0.0.0")
        run_server(host=host, port=port)
    elif args.command in ("ui", "streamlit"):
        port = getattr(args, "port", 8501)
        run_streamlit(port=port)
    elif args.command == "test":
        run_tests()
    elif args.command == "backup":
        run_cli_backup(args.folder, args.name)
    elif args.command == "dr":
        run_cli_dr_drill()
    elif args.command == "security-scan":
        run_cli_security_scan(args.folder)
    elif args.command == "health":
        run_cli_health()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

