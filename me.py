    # Check Bearer header first (API / library clients)
    if creds is not None and creds.scheme.lower() == "bearer":
        token = creds.credentials
        # 1) Try JWKS verification (works for real JWTs / id_tokens)
        try:
            return _get_verifier().verify(token)
        except AuthError as exc:
            logger.info("jwks_verify_failed_trying_userinfo", reason=exc.reason)

        # 2) Fall back to userinfo (works for opaque access tokens from SSO)
        settings = _get_settings()
        try:
            import httpx
            resp = httpx.get(
                str(settings.oidc_userinfo_endpoint),
                headers={"Authorization": f"Bearer {token}"},
                verify=False,
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            logger.warning("userinfo_failed", status=resp.status_code)
        except Exception as exc:
            logger.warning("userinfo_error", error=str(exc))

        # both failed -> reject
        logger.warning("auth_rejected", path=request.url.path, ip=client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
