"""Authentication: a request is authorised by EITHER a bearer API key OR a
valid session cookie (set on UI login)."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from .storage import Storage

SESSION_COOKIE = "qcg_session"


def get_storage(request: Request) -> Storage:
    return request.app.state.storage


def _authenticate(request: Request, storage: Storage) -> str:
    """Resolve the caller to a username via bearer API key or session cookie."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        owner = storage.verify_api_key(token)
        if owner:
            return owner
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        user = storage.session_user(cookie)
        if user:
            return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required (bearer API key or login session)",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_auth_allow_pending(request: Request,
                               storage: Storage = Depends(get_storage)) -> str:
    """Authenticated caller, even if they still owe a password change.

    Only the endpoints needed to *recover* (read identity, change password,
    log out) use this; everything else uses :func:`require_auth`.
    """
    return _authenticate(request, storage)


def require_auth(request: Request, storage: Storage = Depends(get_storage)) -> str:
    """Return the authenticated username, or raise 401.

    A bearer API key authenticates as its owning user, so RBAC and audit apply
    uniformly whether a human (session) or a script (API key) is calling. A user
    who was issued a temporary password must set a new one before any other
    action is permitted.
    """
    user = _authenticate(request, storage)
    if storage.must_change_password(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="you must set a new password before continuing",
        )
    return user


def require_admin(username: str = Depends(require_auth),
                 storage: Storage = Depends(get_storage)) -> str:
    """Require the authenticated user to be an administrator."""
    if not storage.is_admin(username):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="administrator privilege required")
    return username
