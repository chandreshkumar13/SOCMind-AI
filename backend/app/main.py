import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from app.core.auth import session_cookie_secure, validate_auth_config
from app.core.config import settings
from app.core.runtime import process_model_note, worker_processes
from app.api.v1.router import api_router

# A misconfigured token setup stops the application at startup instead of leaving it open or unusable
validate_auth_config(settings.AUTH_MODE, settings.AUTH_TOKENS, settings.ENVIRONMENT, cookie_secure=session_cookie_secure(),
                     allow_guest=settings.ALLOW_GUEST)
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
    if settings.AUTH_MODE == "accounts":
        from app.db.session import SessionLocal
        from app.services import accounts as account_service
        db = SessionLocal()
        try:
            if account_service.setup_required(db):
                logger.warning("AUTH_MODE=accounts and no account exists yet. Open the web page to create the first "
                               "administrator (offered only while no account exists, so do it before anyone else can reach the "
                               "server), or run: python -m app.cli.accounts create-user --username NAME --role approver")
            elif account_service.user_count(db) == 0:
                logger.warning("AUTH_MODE=accounts and every account is disabled. Enable one with: "
                               "python -m app.cli.accounts enable-user --username NAME")
        finally:
            db.close()
        if settings.ALLOW_GUEST:
            logger.warning("ALLOW_GUEST is on: anyone who can reach the sign-in page can open a read-only guest session.")
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


# Validation errors answer 422 as FastAPI does by default, except that the sign-in, account and password endpoints (/auth/...)
# never send the submitted values back: the default answer repeats the whole request body for a missing field, and that body
# holds a password.
@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    if request.url.path.startswith(f"{settings.API_V1_STR}/auth/"):
        errors = [{key: value for key, value in error.items() if key != "input"} for error in errors]
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


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
