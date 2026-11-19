import json
from pathlib import Path
from backend.app.config import BASE_DIR
from backend.app.main import (
    serve_service_worker, serve_manifest, serve_offline,
    serve_frontend_root, health_check
)

def test_pwa_manifest():
    response = serve_manifest()
    assert response.status_code == 200
    assert response.media_type == "application/manifest+json"
    manifest_path = Path(response.path)
    assert manifest_path.exists()
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["name"] == "CloudVault – Cloud-Based Backup & Recovery"
    assert data["display"] == "standalone"
    assert len(data["icons"]) >= 2
    for icon in data["icons"]:
        assert "src" in icon
        assert "sizes" in icon

def test_service_worker():
    response = serve_service_worker()
    assert response.status_code == 200
    assert response.media_type == "application/javascript"
    sw_path = Path(response.path)
    assert sw_path.exists()
    
    content = sw_path.read_text(encoding="utf-8")
    # Verify strict security requirement: /api/ bypass
    assert "url.pathname.startsWith('/api/')" in content
    assert "caches.match('/offline.html')" in content
    assert "cloudvault-static-v1" in content

def test_offline_page():
    response = serve_offline()
    assert response.status_code == 200
    assert response.media_type == "text/html"
    offline_path = Path(response.path)
    assert offline_path.exists()
    
    content = offline_path.read_text(encoding="utf-8")
    assert "You Are Offline" in content
    assert "Check Connection & Reload" in content

def test_frontend_root():
    response = serve_frontend_root()
    assert response.status_code == 200
    root_path = Path(response.path)
    assert root_path.exists()
    
    content = root_path.read_text(encoding="utf-8")
    assert "CloudVault" in content
    assert 'rel="manifest"' in content
    assert "mobile-bottom-nav" in content

def test_health_endpoint():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "CloudVault Core"
    assert "storage_provider" in res

def test_pwa_icons_exist():
    icons_dir = BASE_DIR / "frontend" / "icons"
    assert (icons_dir / "icon.svg").exists()
    assert (icons_dir / "icon-192.png").exists()
    assert (icons_dir / "icon-512.png").exists()
    assert (icons_dir / "icon-192.png").stat().st_size > 0
    assert (icons_dir / "icon-512.png").stat().st_size > 0

