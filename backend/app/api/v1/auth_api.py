from typing import Any, Dict

from fastapi import APIRouter, Depends

from app.core.auth import Principal, current_principal

router = APIRouter()


@router.get("/auth/me", summary="Who am I (mode, name and role of the caller)")
def who_am_i(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    """In disabled mode no one is authenticated and every action is allowed (demo). In token mode the name and role come
    from the token; the role shown is the one that decides what the caller may do."""
    return {"mode": principal.mode, "authenticated": principal.authenticated, "name": principal.name, "role": principal.role}
