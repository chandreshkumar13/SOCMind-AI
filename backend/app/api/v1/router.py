from fastapi import APIRouter
from app.api.v1 import health, alerts_api, audit_api, incidents_api, pipeline_api

api_router = APIRouter()

# Include health routes
api_router.include_router(health.router, tags=["Health & Status"])
# Include alerts routes
api_router.include_router(alerts_api.router, tags=["Alerts Management"])
# Include audit log routes
api_router.include_router(audit_api.router, tags=["Audit Log"])
# Include incident routes (correlation, investigation, response recommendations, human review)
api_router.include_router(incidents_api.router, tags=["Incidents"])
# Include pipeline routes (orchestration and agent status)
api_router.include_router(pipeline_api.router, tags=["Pipeline & Agents"])
