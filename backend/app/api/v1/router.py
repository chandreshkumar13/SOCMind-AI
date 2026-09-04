from fastapi import APIRouter
from app.api.v1 import health, alerts_api

api_router = APIRouter()

# Include health routes
api_router.include_router(health.router, tags=["Health & Status"])
# Include alerts routes
api_router.include_router(alerts_api.router, tags=["Alerts Management"])
