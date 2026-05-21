from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os, sys, importlib, platform

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from database import init_db

app = FastAPI(
    title="ForenCore API",
    description="Professional Forensic Acquisition & Analysis Workstation",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _load(module, attr):
    try:
        mod = importlib.import_module(module)
        return getattr(mod, attr)
    except Exception as e:
        print(f"[WARN] Could not load {module}.{attr}: {e}")
        return None

for r in [
    _load("routers.all_routers", "system_router"),
    _load("routers.all_routers", "ram_capture_router"),
    _load("routers.all_routers", "ram_analysis_router"),
    _load("routers.all_routers", "disk_imaging_router"),
    _load("routers.all_routers", "disk_analysis_router"),
    _load("routers.all_routers", "recovery_router"),
    _load("routers.all_routers", "partition_router"),
    _load("routers.all_routers", "reports_router"),
    _load("routers.all_routers", "utils_router"),
]:
    if r is not None:
        app.include_router(r)

@app.on_event("startup")
async def startup():
    init_db()
    os.makedirs(os.path.join(BASE_DIR, "..", "evidence"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "..", "reports"),  exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "..", "recovered"),exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "..", "sessions"), exist_ok=True)
    print("=" * 54)
    print("  ForenCore Forensic Workstation — ONLINE")
    print(f"  Platform : {platform.system()} {platform.release()}")
    print("  API Docs : http://localhost:8000/api/docs")
    print("=" * 54)

@app.get("/api/health")
def health():
    return {"status": "online", "app": "ForenCore", "version": "1.0.0",
            "platform": platform.system()}
