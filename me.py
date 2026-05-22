"""OIDC authorization-code flow ==> login redirect + callback."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode

import httpx
import redis
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

from src.auth.config import AuthSettings
from loguru import logger

# Reuse the same Redis the stack already runs
_redis = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://api_redis:6379/0"),
    decode_responses=True,
)

CLI_STASH_PREFIX = "cli_auth:"
CLI_STASH_TTL = 60  # seconds, short-lived by design

router = APIRouter(tags=["auth"])


def _settings() -> AuthSettings:
    return AuthSettings()


_AUTHORIZE_URL = (
    "https://ssoforms.dev.echonet/affwebservices/CASSO/oidc/CMPPCIA_api/authorize"
)
_TOKEN_URL = (
    "https://ssoforms.dev.echonet/affwebservices/CASSO/oidc/CMPPCIA_api/token"
)


@router.get("/auth/login")
async def login(request: Request):
    """Redirect user to SSO login page."""
    request.session.clear()
    settings = _settings()

    code_verifier = secrets.token_urlsafe(64)
    code_challenge = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge_b64 = base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode()

    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    request.session["code_verifier"] = code_verifier

    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": f"{settings.public_domain}/auth/callback",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge_b64,
        "code_challenge_method": "S256",
    }
    redirect_url = f"{_AUTHORIZE_URL}?{urlencode(params)}"
    return RedirectResponse(url=redirect_url)


@router.get("/auth/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    """Handle SSO callback: exchange code for tokens.

    Two kinds of login arrive here:
      - Browser logins  -> state was stored in the session; validate it,
                            store the token in the session, redirect to /.
      - CLI/library logins -> state starts with 'cli-'; there is NO session
                            cookie, so skip session validation and stash the
                            token in Redis for the polling client.
    """
    settings = _settings()

    is_cli = state.startswith("cli-")

    if is_cli:
        # CLI flow: no browser session, no PKCE verifier.
        code_verifier = ""
    else:
        # Browser flow: validate state against the session.
        saved_state = request.session.get("oauth_state")
        if not saved_state or saved_state != state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OAuth state",
            )
        code_verifier = request.session.get("code_verifier", "")

    token_data = {
        "grant_type": "authorization_code",
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
        "code": code,
        "redirect_uri": f"{settings.public_domain}/auth/callback",
    }
    # Only browser logins use PKCE (SSO has it disabled, but we keep parity).
    if code_verifier:
        token_data["code_verifier"] = code_verifier

    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(_TOKEN_URL, data=token_data)

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Token exchange failed: {resp.text}",
        )

    tokens = resp.json()
    logger.info(f"TOKEN_KEYS : {list(tokens.keys())}")
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No access_token in SSO response",
        )

    # --- CLI/library login: stash in Redis for the polling client ---
    if is_cli:
        _redis.setex(
            CLI_STASH_PREFIX + state,
            CLI_STASH_TTL,
            json.dumps(tokens),
        )
        return HTMLResponse(
            "<h2>QDI login complete</h2>"
            "<p>You can close this tab and return to your terminal.</p>"
        )

    # --- Browser login: store token in session, redirect home ---
    request.session["access_token"] = access_token
    if id_token:
        request.session["id_token"] = id_token

    request.session.pop("oauth_state", None)
    request.session.pop("code_verifier", None)

    return RedirectResponse(url="/")


@router.get("/auth/logout")
async def logout(request: Request):
    """Clear session and redirect to home."""
    request.session.clear()
    return RedirectResponse(url="/")


@router.get("/auth/exchange")
async def auth_exchange(session: str):
    """Polled by the client. Returns the token once, then deletes it."""
    if not session.startswith("cli-"):
        raise HTTPException(status_code=400, detail="invalid session")

    key = CLI_STASH_PREFIX + session
    data = _redis.get(key)
    if data is None:
        # Not ready yet (or expired) — client keeps polling.
        return JSONResponse({"status": "pending"}, status_code=202)

    _redis.delete(key)  # single-use: consume on first fetch
    return JSONResponse({"status": "ready", "token": json.loads(data)})
