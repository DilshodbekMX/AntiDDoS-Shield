#!/bin/bash

# Anti-DDoS Dashboard Startup Script
# Starts both FastAPI backend and React frontend

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load nvm for modern Node.js (system node v12 is too old for Vite)
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [ -s "$NVM_DIR/nvm.sh" ]; then
    set +e
    . "$NVM_DIR/nvm.sh"
    set -e
fi
# Fallback: add nvm node to PATH directly if nvm.sh didn't work
if [ -d "$NVM_DIR/versions/node" ]; then
    NVM_NODE_DIR=$(ls -d "$NVM_DIR/versions/node/"v* 2>/dev/null | sort -V | tail -1)
    if [ -n "$NVM_NODE_DIR" ] && [ -x "$NVM_NODE_DIR/bin/node" ]; then
        export PATH="$NVM_NODE_DIR/bin:$PATH"
    fi
fi

echo "=========================================="
echo "  Anti-DDoS Dashboard"
echo "=========================================="

# Load environment variables
if [ -f "$SCRIPT_DIR/backend/.env" ]; then
    echo "Loading environment from backend/.env"
    export $(grep -v '^#' "$SCRIPT_DIR/backend/.env" | xargs)
else
    echo "WARNING: backend/.env not found!"
    echo "Creating from .env.example..."
    cp "$SCRIPT_DIR/backend/.env.example" "$SCRIPT_DIR/backend/.env"
    export $(grep -v '^#' "$SCRIPT_DIR/backend/.env" | xargs)
fi

# Verify Node.js version (Vite requires Node 18+)
NODE_VER=$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)
echo "Using Node.js $(node --version 2>/dev/null) from $(which node 2>/dev/null)"
if [ -z "$NODE_VER" ] || [ "$NODE_VER" -lt 18 ]; then
    echo "ERROR: Node.js 18+ required, found v${NODE_VER:-none}. Install via nvm or update system node."
    echo "  nvm install --lts"
    exit 1
fi

# Check for required dependencies
echo ""
echo "Checking dependencies..."

# Check Python dependencies
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "Installing Python dependencies..."
    pip install fastapi uvicorn pydantic python-jose passlib
fi

# Check Node dependencies
if [ ! -d "$SCRIPT_DIR/dashboard/node_modules" ]; then
    echo "Installing Node dependencies..."
    cd "$SCRIPT_DIR/dashboard"
    npm install
    cd "$SCRIPT_DIR"
fi

echo ""
echo "Starting services..."
echo ""

# Start FastAPI backend
cd "$SCRIPT_DIR/backend"
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Wait for backend to start and verify it's healthy
echo "Waiting for backend to start..."
RETRIES=0
MAX_RETRIES=10
while [ $RETRIES -lt $MAX_RETRIES ]; do
    if kill -0 $BACKEND_PID 2>/dev/null; then
        # Process is running, check if port is listening
        if command -v curl >/dev/null 2>&1; then
            if curl -sf http://localhost:8000/docs >/dev/null 2>&1; then
                echo "Backend started successfully (PID $BACKEND_PID)"
                break
            fi
        else
            # No curl, just check process is alive after delay
            if [ $RETRIES -ge 3 ]; then
                echo "Backend process running (PID $BACKEND_PID)"
                break
            fi
        fi
    else
        echo "ERROR: Backend process died during startup"
        echo "Check logs above for details"
        exit 1
    fi
    RETRIES=$((RETRIES + 1))
    sleep 1
done

if [ $RETRIES -ge $MAX_RETRIES ]; then
    echo "ERROR: Backend failed to become ready within ${MAX_RETRIES}s"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

# Start React dashboard
cd "$SCRIPT_DIR/dashboard"
npm run dev &
FRONTEND_PID=$!

# Verify frontend started
sleep 2
if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    echo "ERROR: Frontend process died during startup"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

echo ""
echo "=========================================="
echo "  Services Started!"
echo "=========================================="
echo ""
echo "  Dashboard:  http://localhost:5173"
echo "  API:        http://localhost:8000"
echo "  API Docs:   http://localhost:8000/docs"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "=========================================="
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "Done."
}

trap cleanup EXIT INT TERM

# Wait for processes
wait
