#!/usr/bin/env bash
# ==============================================================
# SGX Vault Web Frontend — Launch Script
# ==============================================================
# This script:
#   1. Builds the SGX vault app (if not already built)
#   2. Installs Python dependencies
#   3. Starts the Flask backend server
#   4. Opens the web frontend in the default browser
#
# Usage:
#   ./start.sh            # start server only
#   ./start.sh --browser  # start server + open browser
# ==============================================================

set -euo pipefail
cd "$(dirname "$0")"

# ---- Build the SGX app if needed ----
APP_BINARY="../app"
if [ ! -f "$APP_BINARY" ]; then
    echo ">>> Building SGX vault app..."
    make -C .. clean all
    if [ ! -f "$APP_BINARY" ]; then
        echo "ERROR: Failed to build $APP_BINARY"
        exit 1
    fi
fi

# ---- Python virtual environment ----
VENV_DIR=".venv"
echo ">>> Setting up Python virtual environment..."
if ! python3 -c "import ensurepip" &>/dev/null; then
    echo "    Installing python3-venv..."
    sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv
fi
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install -q -r backend/requirements.txt

# ---- Start backend ----
echo ">>> Starting SGX Vault backend on http://127.0.0.1:8848 ..."
echo
python backend/server.py &
BACKEND_PID=$!
trap "kill $BACKEND_PID 2>/dev/null; exit" INT TERM EXIT

# Give the backend a second to start
sleep 1

# ---- Optionally open browser ----
if [[ "${1:-}" == "--browser" ]]; then
    HTML_FILE="$(pwd)/index.html"
    if command -v xdg-open &>/dev/null; then
        xdg-open "file://$HTML_FILE" 2>/dev/null || true
    elif command -v open &>/dev/null; then
        open "file://$HTML_FILE" 2>/dev/null || true
    fi
    echo ">>> Frontend opened in browser."
fi

echo ">>> Backend running. Press Ctrl+C to stop."
wait "$BACKEND_PID"
