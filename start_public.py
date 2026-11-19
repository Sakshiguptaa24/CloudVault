import os
import sys
import time
import re
import subprocess
import socket
from pathlib import Path

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def main():
    base_dir = Path(__file__).resolve().parent
    lan_ip = get_lan_ip()
    python_bin = sys.executable
    cloudflared_bin = base_dir / "cloudflared.exe"

    if not cloudflared_bin.exists():
        print(f"Error: {cloudflared_bin} not found!")
        sys.exit(1)

    print("=======================================================")
    print("  ☁️  CloudVault - Multi-Device & Public Tunnel Launcher")
    print("=======================================================")
    print(f"  Starting local FastAPI server on 0.0.0.0:8000 ...")

    # 1. Start Uvicorn Server
    server_proc = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=str(base_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    # Allow server to initialize
    time.sleep(2)

    # 2. Start Cloudflare Tunnel
    print("  Connecting Cloudflare secure HTTPS tunnel ...")
    cf_proc = subprocess.Popen(
        [str(cloudflared_bin), "tunnel", "--url", "http://127.0.0.1:8000", "--no-autoupdate"],
        cwd=str(base_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    # 3. Read Cloudflare tunnel logs to capture the public URL
    public_url = None
    start_time = time.time()
    url_pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")

    while time.time() - start_time < 35:
        line = cf_proc.stdout.readline()
        if not line:
            if cf_proc.poll() is not None:
                print(f"Cloudflared exited unexpectedly with code {cf_proc.returncode}")
                break
            continue
        
        match = url_pattern.search(line)
        if match and "api.trycloudflare.com" not in match.group(0):
            public_url = match.group(0)
            break

    print("=======================================================")
    if public_url:
        print(f"  SUCCESS! Public CloudVault Link Ready Everywhere:")
        print(f"  PUBLIC_URL: {public_url}")
    else:
        print(f"  Warning: Cloudflare URL could not be detected in time.")
    print(f"  LOCAL_LAPTOP: http://localhost:8000")
    print(f"  LAN_MULTIPLE_DEVICES: http://{lan_ip}:8000")
    print("=======================================================\n")
    sys.stdout.flush()

    # Keep both processes running
    try:
        while True:
            # Check if server died
            if server_proc.poll() is not None:
                print(f"Server process terminated with code {server_proc.returncode}")
                break
            # Check if tunnel died
            if cf_proc.poll() is not None:
                print(f"Tunnel process terminated with code {cf_proc.returncode}")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping CloudVault server and tunnel...")
    finally:
        server_proc.terminate()
        cf_proc.terminate()

if __name__ == "__main__":
    main()

