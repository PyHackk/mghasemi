import os
import json
import redis

# reuse the same Redis the stack already runs
_redis = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://api_redis:6379/0"),
    decode_responses=True,
)

CLI_STASH_PREFIX = "cli_auth:"
CLI_STASH_TTL = 60  # seconds, short-lived by design







    # If this login came from the CLI/library (state carries its session id),
    # stash the token in Redis for the polling client instead of redirecting.
    cli_session = request.query_params.get("state", "")
    if cli_session.startswith("cli-"):
        _redis.setex(
            CLI_STASH_PREFIX + cli_session,
            CLI_STASH_TTL,
            json.dumps(token_response),
        )
        return HTMLResponse(
            "<h2>QDI login complete</h2>"
            "<p>You can close this tab and return to your terminal.</p>"
        )
    # ...otherwise your existing browser/session redirect continues as before






@router.get("/auth/exchange")
async def auth_exchange(session: str):
    """Polled by the client. Returns the token once, then deletes it."""
    if not session.startswith("cli-"):
        raise HTTPException(status_code=400, detail="invalid session")

    key = CLI_STASH_PREFIX + session
    data = _redis.get(key)
    if data is None:
        # not ready yet (or expired) — client keeps polling
        return JSONResponse({"status": "pending"}, status_code=202)

    _redis.delete(key)  # single-use: consume on first fetch
    return JSONResponse({"status": "ready", "token": json.loads(data)})






"""Server-callback OIDC flow.

Opens the browser to SSO, which redirects to the QDI server's own trusted
callback. The server stashes the token in Redis; this client polls the
server's /auth/exchange endpoint until the token is ready. No local server,
no self-signed certificates, no browser warnings.
"""
import secrets
import time
import urllib.parse
import webbrowser

import httpx

from .base import AuthStrategy
from ..config import QDIConfig
from ..exceptions import AuthenticationError


class ServerCallbackStrategy(AuthStrategy):
    def __init__(self, config: QDIConfig):
        self._config = config

    def authenticate(self) -> dict:
        session_id = "cli-" + secrets.token_urlsafe(32)
        self._open_browser(session_id)
        return self._poll_for_token(session_id)

    def _open_browser(self, session_id: str) -> None:
        cfg = self._config
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": cfg.client_id,
                "redirect_uri": cfg.server_callback_url,
                "scope": cfg.scope,
                "state": session_id,
            }
        )
        auth_url = f"{cfg.authorize_url}?{query}"
        print("Opening your browser to sign in via SSO...")
        webbrowser.open(auth_url)

    def _poll_for_token(self, session_id: str) -> dict:
        cfg = self._config
        exchange_url = f"{cfg.api_base_url}/auth/exchange"
        deadline = time.time() + 300  # 5 minutes to complete login

        with httpx.Client(verify=cfg.verify_ssl, timeout=10) as http:
            while time.time() < deadline:
                try:
                    resp = http.get(exchange_url, params={"session": session_id})
                except httpx.HTTPError:
                    time.sleep(1.5)
                    continue

                if resp.status_code == 202:
                    time.sleep(1.5)  # still pending, keep polling
                    continue
                if resp.status_code == 200:
                    return resp.json()["token"]
                raise AuthenticationError(
                    f"Exchange failed ({resp.status_code}): {resp.text[:200]}"
                )

        raise AuthenticationError("Timed out waiting for SSO login.")









    @property
    def server_callback_url(self) -> str:
        return f"{self.api_base_url}/auth/callback"







from .base import AuthStrategy
from .server_callback import ServerCallbackStrategy

__all__ = ["AuthStrategy", "ServerCallbackStrategy"]






from .auth import AuthStrategy, ServerCallbackStrategy
# ...
        self._auth = auth_strategy or ServerCallbackStrategy(self._config)







    def whoami(self) -> dict:
        """Fetch the current user and greet them."""
        me = self._get("/api/me")
        name = me.get("name") or me.get("given_name") or "there"
        email = me.get("email", "")
        print(f"\n✓ Welcome, {name} ({email})\n")
        return me








