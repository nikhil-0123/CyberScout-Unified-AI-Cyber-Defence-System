#!/usr/bin/env bash
# Start the FastAPI server for CyberScout / PhishGuard

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "Starting CyberScout API on ${HOST}:${PORT}..."
echo "API Docs available at: http://localhost:${PORT}/docs"
echo "Press Ctrl+C to stop the server"
echo ""

cd "$(dirname "$0")"
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
fi

python -m uvicorn src.api_fastapi:app --reload --host "$HOST" --port "$PORT"
