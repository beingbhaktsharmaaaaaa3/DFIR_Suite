from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os, sys, importlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from database import init_db, SessionLocal
from auth import create_default_admin

app = FastAPI(
    title="DFIR Investigation Suite API",
    description="AI-powered forensic investigation platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _load(module_path, attr):
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    except Exception as e:
        print(f"[WARN] Skipping {module_path}.{attr}: {e}")
        return None

for r in [
    _load("routers.misc_routers", "auth_router"),
    _load("routers.misc_routers", "dashboard_router"),
    _load("routers.cases",        "router"),
    _load("routers.evidence",     "router"),
    _load("routers.artifacts",    "router"),
    _load("routers.timeline",     "router"),
    _load("routers.iocs",         "router"),
    _load("routers.scanner",      "router"),
    _load("routers.ai_assistant", "router"),
    _load("routers.misc_routers", "users_router"),
    _load("routers.misc_routers", "network_router"),
    _load("routers.misc_routers", "persistence_router"),
    _load("routers.misc_routers", "reports_router"),
]:
    if r is not None:
        app.include_router(r)

@app.on_event("startup")
async def startup():
    init_db()
    db = SessionLocal()
    try:
        create_default_admin(db)
    finally:
        db.close()
    print("=" * 52)
    print("  DFIR Suite API — ONLINE")
    print("  http://localhost:8000/api/docs")
    print("  Login: admin / Admin@1234")
    print("=" * 52)

@app.get("/api/health")
def health():
    return {"status": "online", "app": "DFIR Investigation Suite", "version": "1.0.0"}
