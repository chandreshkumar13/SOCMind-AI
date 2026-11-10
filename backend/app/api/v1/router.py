from fastapi import APIRouter, Depends
from app.api.v1 import auth_api, health, alerts_api, audit_api, incidents_api, pipeline_api, system_api
from app.core.auth import current_principal, require

api_router = APIRouter()

# Health and version stay public so that monitoring can reach them without a token
api_router.include_router(health.router, tags=["Health & Status"])
# Who am I: any valid caller (in token mode, a token is required)
api_router.include_router(auth_api.router, tags=["Authentication"], dependencies=[Depends(current_principal)])
# Every other router needs at least the viewer role. Routes that change data add a stricter check of their own.
api_router.include_router(alerts_api.router, tags=["Alerts Management"], dependencies=[Depends(require("viewer"))])
api_router.include_router(audit_api.router, tags=["Audit Log"], dependencies=[Depends(require("viewer"))])
api_router.include_router(incidents_api.router, tags=["Incidents"], dependencies=[Depends(require("viewer"))])
api_router.include_router(pipeline_api.router, tags=["Pipeline & Agents"], dependencies=[Depends(require("viewer"))])
api_router.include_router(system_api.router, tags=["System"], dependencies=[Depends(require("viewer"))])
