import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from app.core.auth import validate_auth_config
from app.core.config import settings
from app.core.runtime import process_model_note, worker_processes
from app.api.v1.router import api_router

# A misconfigured token setup stops the application at startup instead of leaving it open or unusable
validate_auth_config(settings.AUTH_MODE, settings.AUTH_TOKENS, settings.ENVIRONMENT)
from app.db.session import init_db
from app.services.threat_intel import resolve_provider


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on startup
    init_db()
    choice = resolve_provider()
    logger.info("Threat intelligence provider: %s%s", choice.active, f" ({choice.reason})" if choice.reason else "")
    note = process_model_note(worker_processes(), live_provider=choice.active == "virustotal")
    if note:
        logger.warning(note)
    yield

# Also ensure DB tables exist upon module import
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="SOCMind AI: Multi-Agent Autonomous Threat Triage & Incident Response Copilot API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],   # lets the browser read the list totals (see frontend/src/api.js apiPage)
)

logging.basicConfig(level=getattr(logging, str(settings.LOG_LEVEL).upper(), logging.INFO),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("socmind")
# httpx logs every request URL at INFO; keep indicator values and provider URLs out of the application log
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


# Global Error Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url.path)  # details stay in the server log
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred. See server logs for details.",
            "path": request.url.path
        }
    )

# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", summary="Root Endpoint")
def root():
    return {
        "message": "Welcome to SOCMind AI Backend API",
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
