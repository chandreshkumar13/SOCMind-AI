from fastapi import APIRouter, Depends
from app.api.v1 import auth_api, health, alerts_api, audit_api, incidents_api, pipeline_api, system_api
from app.core.auth import require

api_router = APIRouter()

# Health and version stay public so that monitoring can reach them without a token
api_router.include_router(health.router, tags=["Health & Status"])
# Sign-in, sign-out and who am I. Each route in auth_api declares its own requirement: status and login are public, the rest
# need a valid caller. A router-wide dependency here would block sign-in itself.
api_router.include_router(auth_api.router, tags=["Authentication"])
# Every other router needs at least the viewer role. Routes that change data add a stricter check of their own.
api_router.include_router(alerts_api.router, tags=["Alerts Management"], dependencies=[Depends(require("viewer"))])
api_router.include_router(audit_api.router, tags=["Audit Log"], dependencies=[Depends(require("viewer"))])
api_router.include_router(incidents_api.router, tags=["Incidents"], dependencies=[Depends(require("viewer"))])
api_router.include_router(pipeline_api.router, tags=["Pipeline & Agents"], dependencies=[Depends(require("viewer"))])
api_router.include_router(system_api.router, tags=["System"], dependencies=[Depends(require("viewer"))])
