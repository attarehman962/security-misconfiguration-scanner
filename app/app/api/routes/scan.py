from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user
from app.models.user import User


router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("")
async def run_scan(
    target_url: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, object]:
    """Run a security scan for the authenticated user."""
    return {
        "requested_by": current_user.email,
        "target_url": target_url,
        "message": "Scan route is protected.",
    }
