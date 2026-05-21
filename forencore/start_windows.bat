@echo off
title ForenCore — Forensic Workstation
color 0D
cls

echo.
echo  ============================================================
echo   ForenCore — Professional Forensic Workstation v1.0
echo   Forensic Acquisition, Analysis and Recovery Suite
echo  ============================================================
echo.

set "BASEDIR=%~dp0"
set "BACKENDDIR=%~dp0backend"
set "FRONTENDDIR=%~dp0frontend"

:: ── Kill anything on port 8000 ───────────────────────────────────
echo  [*] Clearing port 8000...
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8000 "') do (
    taskkill /f /pid %%a >nul 2>&1
)

:: ── Check Python ─────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found!
    echo  Install Python 3.10+ from https://www.python.org/downloads/
    echo  CHECK "Add Python to PATH" during installation!
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [OK] %%v

:: ── Install packages with bcrypt fix ────────────────────────────
echo  [*] Installing required packages...
pip install "bcrypt==3.2.2" -q --no-warn-script-location
pip install "passlib[bcrypt]==1.7.4" -q --no-warn-script-location
pip install fastapi "uvicorn[standard]" sqlalchemy "python-jose[cryptography]" ^
            "pydantic[email]" aiofiles httpx python-multipart psutil reportlab ^
            -q --no-warn-script-location
echo  [OK] Packages ready.

:: ── Create working directories ───────────────────────────────────
if not exist "%BASEDIR%evidence"  mkdir "%BASEDIR%evidence"
if not exist "%BASEDIR%reports"   mkdir "%BASEDIR%reports"
if not exist "%BASEDIR%recovered" mkdir "%BASEDIR%recovered"
if not exist "%BASEDIR%sessions"  mkdir "%BASEDIR%sessions"
if not exist "%BASEDIR%tools"     mkdir "%BASEDIR%tools"

echo.
echo  ============================================================
echo   TOOL SETUP NOTES
echo  ============================================================
echo   For full RAM analysis:   pip install volatility3
echo   For full disk analysis:  pip install pytsk3
echo   For file carving:        Install photorec (testdisk package)
echo   For partition recovery:  Install testdisk
echo   For RAM capture (Win):   Download WinPMEM to tools\
echo  ============================================================
echo.

:: ── Open browser after 5s ────────────────────────────────────────
echo  [*] Starting ForenCore backend...
echo  [*] URL:   http://localhost:8000
echo  [*] Docs:  http://localhost:8000/api/docs
echo  [*] Browser opens in 5 seconds — keep this window open!
echo.

powershell -Command "Start-Sleep 5; Start-Process '%FRONTENDDIR%\index.html'" >nul 2>&1 &

:: ── Start backend ────────────────────────────────────────────────
cd /d "%BACKENDDIR%"
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level info

echo.
echo  [!] ForenCore stopped. Press any key to exit.
pause
