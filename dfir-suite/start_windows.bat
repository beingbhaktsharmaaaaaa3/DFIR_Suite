@echo off
title DFIR Investigation Suite
color 0A
cls

echo.
echo  ====================================================
echo   DFIR Investigation Suite v1.0
echo  ====================================================
echo.

:: ── Set base dir (handles spaces in path) ────────────────────────
set "BASEDIR=%~dp0"
set "BACKENDDIR=%~dp0backend"
set "FRONTENDDIR=%~dp0frontend"

:: ── Kill any old process on port 8000 ────────────────────────────
echo  [*] Clearing port 8000...
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8000 "') do (
    taskkill /f /pid %%a >nul 2>&1
)

:: ── Check Python ─────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found!
    echo  Download Python 3.10+ from: https://www.python.org/downloads/
    echo  IMPORTANT: Check "Add Python to PATH" when installing.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [OK] %%v

:: ── Install packages (pin bcrypt to fix Python 3.14 issue) ───────
echo  [*] Installing packages...
pip install "bcrypt==3.2.2" -q --no-warn-script-location
pip install "passlib[bcrypt]==1.7.4" -q --no-warn-script-location
pip install fastapi "uvicorn[standard]" sqlalchemy "python-jose[cryptography]" -q --no-warn-script-location
pip install aiofiles httpx "pydantic[email]" python-multipart psutil reportlab -q --no-warn-script-location
echo  [OK] Packages ready.

:: ── Create required folders ───────────────────────────────────────
if not exist "%BASEDIR%evidence_store" mkdir "%BASEDIR%evidence_store"
if not exist "%BASEDIR%reports"        mkdir "%BASEDIR%reports"

:: ── Check Ollama ──────────────────────────────────────────────────
curl -s --connect-timeout 2 http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo  [WARN] Ollama not running - AI features disabled.
    echo  [INFO] To enable: open another terminal and run: ollama serve
    echo  [INFO] Then pull a model:                        ollama pull mistral
) else (
    echo  [OK] Ollama running - AI features enabled.
)

:: ── Open frontend after 6 seconds (quoted path handles spaces) ───
echo.
echo  [*] Backend starting...
echo  [*] URL:   http://localhost:8000
echo  [*] Docs:  http://localhost:8000/api/docs
echo  [*] Login: admin / Admin@1234
echo  [*] Browser opens in 6 seconds - keep this window open!
echo.

:: Use PowerShell to open browser (handles spaces in path better)
powershell -Command "Start-Sleep 6; Start-Process '%FRONTENDDIR%\index.html'" >nul 2>&1 &

:: ── Start backend (single instance, foreground) ───────────────────
cd /d "%BACKENDDIR%"
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level info

echo.
echo  [!] Backend stopped.
pause
