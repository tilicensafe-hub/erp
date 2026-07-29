from fastapi import Header, HTTPException, status

from .config import settings


def require_token(authorization: str | None = Header(default=None)):
    expected = f"Bearer {settings.api_token}"
    if authorization != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido.",
        )

