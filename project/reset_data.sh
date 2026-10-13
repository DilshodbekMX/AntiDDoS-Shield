#!/bin/bash
# Reset all data in the Anti-DDoS system
# This script clears all persistent storage and resets to a clean state

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  Anti-DDoS System Data Reset"
echo "=========================================="
echo ""

# Stop any running services first
echo "[1/7] Stopping services..."
if [ -d ".pids" ]; then
    for pidfile in .pids/*.pid; do
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile" 2>/dev/null)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                echo "  Stopping process $pid..."
                kill "$pid" 2>/dev/null || true
            fi
        fi
    done
    rm -f .pids/*.pid
fi
echo "  Done."

# Clear SQLite database
echo ""
echo "[2/7] Clearing SQLite database..."
rm -f backend/data/antiddos.db
rm -f backend/data/antiddos.db-shm
rm -f backend/data/antiddos.db-wal
echo "  Removed: backend/data/antiddos.db*"

# Clear rules and baselines data
echo ""
echo "[3/7] Clearing rules and baselines..."
if [ -f "data/rules.json" ]; then
    echo '{"whitelist": {}, "blacklist": {}, "protected": {}}' > data/rules.json
    echo "  Reset: data/rules.json"
fi
if [ -f "data/baselines.json" ]; then
    echo '{}' > data/baselines.json
    echo "  Reset: data/baselines.json"
fi

# Reset IP lists
echo ""
echo "[4/7] Resetting IP lists..."
if [ -f "layer1/config/ip_lists.json" ]; then
    echo '{
  "whitelist": [],
  "blacklist": [],
  "protected": []
}' > layer1/config/ip_lists.json
    echo "  Reset: layer1/config/ip_lists.json"
fi

# Reset tenant configuration
echo ""
echo "[5/7] Resetting tenant configuration..."
if [ -f "config/tenants.json" ]; then
    echo '{
  "tenants": [],
  "version": 1
}' > config/tenants.json
    echo "  Reset: config/tenants.json"
fi

# Clear ML models and training data
echo ""
echo "[6/7] Clearing ML models and training data..."
rm -f layer3/trained_models/*.json
rm -f layer3/trained_models/*.pkl
rm -f data/training/*.csv
echo "  Removed: layer3/trained_models/*"
echo "  Removed: data/training/*.csv"

# Clear in-memory DPDK service data via API (if backend is running)
echo ""
echo "[7/8] Clearing in-memory data via API..."
API_URL="${API_URL:-http://localhost:8000}"
if curl -s -X POST "$API_URL/system/reset" \
    -H "Content-Type: application/json" \
    -d '{"clear_per_ip_data": true, "clear_attacks": true, "clear_traffic": true, "reason": "System reset via script"}' \
    --connect-timeout 2 > /dev/null 2>&1; then
    echo "  Cleared in-memory data via API"
else
    echo "  Note: Backend API not running. In-memory data will be cleared on restart."
fi

# Recreate database schema
echo ""
echo "[8/8] Initializing fresh database..."
if [ -f "backend/api/database/init_db.py" ]; then
    cd backend
    python3 -c "
from api.database import engine, Base
from api.database.models import *
Base.metadata.create_all(bind=engine)
print('  Database schema created.')
" 2>/dev/null || echo "  Note: Run 'python -c \"from api.database import init_db; init_db()\"' to initialize DB"
    cd ..
else
    echo "  Note: Database will be initialized on first API startup"
fi

echo ""
echo "=========================================="
echo "  Reset Complete!"
echo "=========================================="
echo ""
echo "All data has been cleared. The system is ready for a fresh start."
echo ""
echo "Next steps:"
echo "  1. Start the backend: cd backend && uvicorn api.main:app --reload"
echo "  2. Start the dashboard: cd dashboard && npm run dev"
echo "  3. Create your first tenant in the Tenants page"
echo ""
