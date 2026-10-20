import sys
import platform
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()


@router.get("/health", summary="Health Check Endpoint")
def health_check():
    """
    Returns application health status and environment details.
    """
    return {
        "status": "healthy",
        "app_name": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "debug": settings.DEBUG,
        "database": settings.DATABASE_URL.split(":")[0]  # engine type only; never expose the URL
    }


@router.get("/version", summary="Version Endpoint")
def version_info():
    """
    Returns system version and runtime metadata.
    """
    return {
        "version": settings.VERSION,
        "python_version": sys.version,
        "platform": platform.platform(),
        "team": {
            "team_number": 150,
            "leader": "Chandresh Kumar",
            "member": "Kalpna Chaudhary",
            "mentor": "Sachin Kumar Yadav"
        }
    }
