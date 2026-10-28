#!/bin/bash
set -e

echo "=== Zorix Backend Starting ==="

python -c "from backend.main import validate_runtime_secret; validate_runtime_secret()"

echo "Applying database migrations..."
alembic -c backend/alembic.ini upgrade head
alembic -c backend/alembic.ini check

echo "Starting FastAPI server..."
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
