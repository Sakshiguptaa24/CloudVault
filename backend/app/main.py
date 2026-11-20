import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.config import settings, BASE_DIR
from backend.app.database import engine, Base
from backend.app.storage import get_storage_provider
from backend.app.routers import auth, backups, recovery, scheduler, ai, security, analytics, dr, events, storage_api
from backend.app.services.scheduler_service import scheduler as background_scheduler

# Create database tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CloudVault API",
    description="Cloud-Based Backup and Recovery System with Deduplication & Integrity Verification",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
origins = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]
if not origins:
    origins = ["*"]

# In production or with wildcard, credentials cannot be enabled with '*'
cors_credentials = True
if "*" in origins:
    cors_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=cors_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With", "Origin"],
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Include API Routers
app.include_router(auth.router)
app.include_router(backups.router)
app.include_router(recovery.router)
app.include_router(scheduler.router)
app.include_router(ai.router)
app.include_router(security.router)
app.include_router(analytics.router)
app.include_router(dr.router)
app.include_router(events.router)
app.include_router(storage_api.router)

# Lifecycle events
@app.on_event("startup")
def on_startup():
    # Enforce production security & durability rules if in production mode
    settings.validate_production_rules()

    # Verify storage provider
    storage = get_storage_provider()
    # Start background scheduler only when not running automated tests
    if not os.environ.get("TESTING"):
        background_scheduler.start()

@app.on_event("shutdown")
def on_shutdown():
    if not os.environ.get("TESTING"):
        background_scheduler.stop()

@app.get("/api/v1/health")
def health_check():
    storage = get_storage_provider()
    return {
        "status": "healthy",
        "service": "CloudVault Core",
        "version": "2.0.0",
        "storage_provider": storage.get_storage_name(),
        "storage_health": storage.health_check(),
        "capabilities": storage.get_capabilities()
    }

@app.get("/api/v1/storage/clouds")
def multi_cloud_status():
    from backend.app.storage import get_multi_cloud_inventory
    return get_multi_cloud_inventory()

# Mount Frontend static files
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/sw.js", include_in_schema=False)
    def serve_service_worker():
        sw_file = frontend_dir / "sw.js"
        if sw_file.exists():
            return FileResponse(str(sw_file), media_type="application/javascript")
        return {"error": "Service Worker not found"}

    @app.get("/manifest.json", include_in_schema=False)
    def serve_manifest():
        m_file = frontend_dir / "manifest.json"
        if m_file.exists():
            return FileResponse(str(m_file), media_type="application/manifest+json")
        return {"error": "Manifest not found"}

    @app.get("/offline.html", include_in_schema=False)
    def serve_offline():
        off_file = frontend_dir / "offline.html"
        if off_file.exists():
            return FileResponse(str(off_file), media_type="text/html")
        return {"error": "Offline page not found"}

    @app.get("/", include_in_schema=False)
    def serve_frontend_root():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"message": "CloudVault API is running. Access /docs for Swagger UI."}
