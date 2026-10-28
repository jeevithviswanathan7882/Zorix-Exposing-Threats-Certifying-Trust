"""FastAPI entry point for the Zorix static analysis service."""
import sys
import os
import logging
import shutil

# Fix Windows UTF-8 encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("zorix")


def validate_runtime_secret() -> None:
    """Refuse known development keys when debug mode is disabled."""
    if not settings.DEBUG and (len(settings.SECRET_KEY) < 32 or settings.SECRET_KEY in {
        "your-secret-key-change-in-production", "change-this-to-a-random-secret-key",
        "your-super-secret-key-change-this-in-production-12345",
    }):
        raise RuntimeError("Set a unique SECRET_KEY before starting Zorix")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — startup and shutdown."""
    logger.info("=" * 60)
    logger.info("Zorix static analysis service starting")
    logger.info("=" * 60)

    validate_runtime_secret()

    logger.info("Database schema is managed by Alembic migrations")

    # Create required directories
    for d in [settings.REPORTS_DIR, settings.LOGS_DIR]:
        Path(d).mkdir(parents=True, exist_ok=True)
    logger.info(f"Database: {settings.DATABASE_URL.split('://')[0] if '://' in settings.DATABASE_URL else 'sqlite'}")
    logger.info(f"Semgrep: {'available' if shutil.which(settings.SEMGREP_PATH) else 'unavailable'}")
    logger.info("=" * 60)

    yield

    logger.info("Zorix shutting down")


app = FastAPI(
    title="Zorix — Repository Static Analysis",
    description="Evidence-based static analysis of authorized GitHub repository files",
    version="3.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- API Routes ----
from backend.api.routes import analysis, auth

app.include_router(analysis.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
# Legacy admin, settings, logs, and WebSocket routes are excluded until they
# have current ownership and authorization tests.


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "3.0.0",
        "services": {
            "semgrep": bool(shutil.which(settings.SEMGREP_PATH)),
        },
    }


@app.get("/api/health")
async def api_health():
    """API health check (proxied)."""
    return await health_check()
