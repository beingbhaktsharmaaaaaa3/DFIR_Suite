#!/bin/bash
clear
echo ""
echo "  ===================================================="
echo "   DFIR Investigation Suite v1.0"
echo "   AI-Powered Forensic Investigation Platform"
echo "  ===================================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "  [ERROR] Python3 not found. Install with: sudo apt install python3 python3-pip"
    exit 1
fi

echo "  [OK] Python $(python3 --version)"

# Install deps
echo "  [*] Checking dependencies..."
cd "$BACKEND_DIR"
pip3 install -r requirements.txt -q --break-system-packages 2>/dev/null || \
pip3 install fastapi uvicorn sqlalchemy passlib python-jose aiofiles httpx reportlab python-multipart psutil -q --break-system-packages 2>/dev/null

# Check Ollama
if curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo "  [OK] Ollama running — AI features enabled"
else
    echo "  [WARN] Ollama not running. Start with: ollama serve"
    echo "  [INFO] Pull a model:  ollama pull mistral"
fi

# Create dirs
mkdir -p "$SCRIPT_DIR/evidence_store"
mkdir -p "$SCRIPT_DIR/reports"

echo ""
echo "  [*] Starting DFIR Backend API on http://localhost:8000 ..."
echo "  [*] API Docs: http://localhost:8000/api/docs"
echo "  [*] Default login: admin / Admin@1234"
echo ""

# Start backend background
cd "$BACKEND_DIR"
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
sleep 3

# Open browser
echo "  [*] Opening frontend..."
if command -v xdg-open &>/dev/null; then
    xdg-open "$FRONTEND_DIR/index.html" &
elif command -v open &>/dev/null; then
    open "$FRONTEND_DIR/index.html" &
else
    echo "  [INFO] Open manually: $FRONTEND_DIR/index.html"
fi

echo ""
echo "  ===================================================="
echo "   DFIR Suite is running! Press Ctrl+C to stop."
echo "  ===================================================="
echo ""

trap "echo '  [*] Stopping...'; kill $BACKEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM
wait $BACKEND_PID
