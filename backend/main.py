from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from database import init_db, SessionLocal
from auth import create_default_admin
from routers.cases import router as cases_router
from routers.evidence import router as evidence_router
from routers.artifacts import router as artifacts_router
from routers.timeline import router as timeline_router
from routers.iocs import router as iocs_router
from routers.scanner import router as scanner_router
from routers.ai_assistant import router as ai_router
from routers.misc_routers import (
    dashboard_router, users_router, network_router,
    persistence_router, reports_router, auth_router
)

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

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(cases_router)
app.include_router(evidence_router)
app.include_router(artifacts_router)
app.include_router(timeline_router)
app.include_router(iocs_router)
app.include_router(scanner_router)
app.include_router(ai_router)
app.include_router(users_router)
app.include_router(network_router)
app.include_router(persistence_router)
app.include_router(reports_router)

@app.on_event("startup")
async def startup():
    init_db()
    db = SessionLocal()
    create_default_admin(db)
    db.close()
    print("✅ DFIR Investigation Suite API started")
    print("📚 Docs: http://localhost:8000/api/docs")

@app.get("/api/health")
def health():
    return {"status": "online", "app": "DFIR Investigation Suite", "version": "1.0.0"}
