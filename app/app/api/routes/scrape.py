from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user
from app.models.user import User


router = APIRouter(prefix="/scrape", tags=["scrape"])


@router.post("")
async def run_scrape(
    target_url: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, object]:
    """Run a scrape job for the authenticated user."""
    return {
        "requested_by": current_user.email,
        "target_url": target_url,
        "message": "Scrape route is protected.",
    }
