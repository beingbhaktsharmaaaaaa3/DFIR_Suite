@echo off
title DFIR Investigation Suite
color 0A
echo.
echo  ====================================================
echo   DFIR Investigation Suite v1.0
echo   AI-Powered Forensic Investigation Platform
echo  ====================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.10+ first.
    echo  Download: https://www.python.org/downloads/
    pause & exit /b 1
)

:: Check pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] pip not found.
    pause & exit /b 1
)

:: Install dependencies if needed
echo  [*] Checking Python dependencies...
cd /d "%~dp0backend"
pip install -r requirements.txt -q --no-warn-script-location 2>nul
if errorlevel 1 (
    echo  [WARN] Some packages failed to install. Trying core packages...
    pip install fastapi uvicorn sqlalchemy passlib python-jose aiofiles httpx reportlab python-multipart psutil -q
)

:: Check Ollama
echo  [*] Checking Ollama status...
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo  [WARN] Ollama not running. AI features will be unavailable.
    echo  [INFO] To enable AI: run 'ollama serve' in another terminal
    echo  [INFO] Then pull a model: 'ollama pull mistral'
) else (
    echo  [OK] Ollama is running
)

:: Create directories
if not exist "..\evidence_store" mkdir "..\evidence_store"
if not exist "..\reports" mkdir "..\reports"

echo.
echo  [*] Starting DFIR Backend API...
echo  [*] API Docs: http://localhost:8000/api/docs
echo  [*] Default login: admin / Admin@1234
echo.

:: Start backend in background
start "DFIR-Backend" /min cmd /c "cd /d "%~dp0backend" && uvicorn main:app --host 0.0.0.0 --port 8000 --reload 2>&1"

:: Wait for backend to start
echo  [*] Waiting for backend to start...
timeout /t 4 /nobreak >nul

:: Open frontend in default browser
echo  [*] Opening DFIR Suite in browser...
start "" "%~dp0frontend\index.html"

echo.
echo  ====================================================
echo   DFIR Suite is running!
echo   Close this window to stop the backend server.
echo  ====================================================
echo.
echo  Press Ctrl+C to stop the server.

:: Keep alive
cd /d "%~dp0backend"
uvicorn main:app --host 0.0.0.0 --port 8000
