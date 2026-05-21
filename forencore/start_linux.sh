#!/bin/bash
clear
echo ""
echo "  ============================================================"
echo "   ForenCore — Professional Forensic Workstation v1.0"
echo "   Forensic Acquisition, Analysis and Recovery Suite"
echo "  ============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
VENV_DIR="$SCRIPT_DIR/venv"

# ── Check Python ─────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "  [ERROR] Python3 not found."
    echo "  Kali/Debian: sudo apt install python3 python3-venv python3-pip -y"
    exit 1
fi
echo "  [OK] $(python3 --version)"

# ── Create virtual environment ───────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "  [*] Creating virtual environment (first run only)..."
    python3 -m venv "$VENV_DIR" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "  [*] Installing venv support..."
        sudo apt install python3-venv python3-full -y 2>/dev/null
        python3 -m venv "$VENV_DIR"
        if [ $? -ne 0 ]; then
            echo "  [ERROR] Could not create venv. Try: sudo apt install python3-venv"
            exit 1
        fi
    fi
    echo "  [OK] Virtual environment created."
else
    echo "  [OK] Virtual environment ready."
fi

source "$VENV_DIR/bin/activate"
echo "  [OK] Virtual environment activated."

# ── Install all packages ─────────────────────────────────────────
echo "  [*] Installing packages..."
pip install --upgrade pip -q 2>/dev/null
pip install \
    "bcrypt==3.2.2" \
    "passlib[bcrypt]==1.7.4" \
    "fastapi==0.111.0" \
    "uvicorn[standard]==0.29.0" \
    "sqlalchemy==2.0.30" \
    "python-jose[cryptography]==3.3.0" \
    "pydantic[email]==2.7.1" \
    "aiofiles==23.2.1" \
    "httpx==0.27.0" \
    "python-multipart==0.0.9" \
    "psutil==5.9.8" \
    "reportlab==4.2.0" \
    -q 2>/dev/null

echo "  [OK] Packages installed."

# ── Create directories ───────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/evidence"
mkdir -p "$SCRIPT_DIR/reports"
mkdir -p "$SCRIPT_DIR/recovered"
mkdir -p "$SCRIPT_DIR/sessions"
mkdir -p "$SCRIPT_DIR/tools"

# ── Optional tools status ────────────────────────────────────────
echo ""
echo "  ── Optional Forensic Tools ────────────────────────────────"
command -v vol &>/dev/null && echo "  [OK] Volatility 3 found" || echo "  [--] Volatility 3 not found  → pip install volatility3"
command -v testdisk &>/dev/null && echo "  [OK] TestDisk found" || echo "  [--] TestDisk not found      → sudo apt install testdisk"
command -v photorec &>/dev/null && echo "  [OK] PhotoRec found" || echo "  [--] PhotoRec not found      → sudo apt install testdisk"
python3 -c "import pytsk3" 2>/dev/null && echo "  [OK] pytsk3 found" || echo "  [--] pytsk3 not found        → pip install pytsk3"
echo "  ────────────────────────────────────────────────────────────"
echo ""

echo "  [*] Starting ForenCore backend on http://localhost:8000 ..."
echo "  [*] API Docs: http://localhost:8000/api/docs"
echo "  [*] Keep this terminal open while using ForenCore!"
echo ""

# ── Open browser ─────────────────────────────────────────────────
(
    sleep 5
    if command -v xdg-open &>/dev/null; then
        xdg-open "$FRONTEND_DIR/index.html" 2>/dev/null
    elif command -v firefox &>/dev/null; then
        firefox "$FRONTEND_DIR/index.html" 2>/dev/null &
    elif command -v chromium-browser &>/dev/null; then
        chromium-browser "$FRONTEND_DIR/index.html" 2>/dev/null &
    elif command -v google-chrome &>/dev/null; then
        google-chrome "$FRONTEND_DIR/index.html" 2>/dev/null &
    else
        echo "  [INFO] Open manually in your browser: $FRONTEND_DIR/index.html"
    fi
) &

# ── Start backend ─────────────────────────────────────────────────
cd "$BACKEND_DIR"
"$VENV_DIR/bin/python" -m uvicorn main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --log-level info

echo ""
echo "  [!] ForenCore stopped."
read -p "  Press Enter to exit..."
