from __future__ import annotations

import base64

from fastapi import Depends, HTTPException, Request

from certadillo.runtime import get_runtime
from certadillo.services import Actor, Platform


def platform():
    with get_runtime().platform() as p:
        yield p


def _credential(request: Request):
    """Split the request's credential into an API key and a JWT bearer.

    A Bearer token that is a `cdl_` key or is not JWT-shaped is treated as an
    API key; a JWT-shaped Bearer (three dot-separated segments) is an OIDC
    token. X-API-Key and EST's HTTP Basic password are always API keys."""
    from certadillo.auth import Credential

    api_key = request.headers.get("x-api-key")
    bearer = None
    auth = request.headers.get("authorization", "")
    low = auth.lower()
    if low.startswith("bearer "):
        tok = auth[7:].strip()
        if tok.count(".") == 2 and not tok.startswith("cdl_"):
            bearer = tok
        else:
            api_key = api_key or tok
    elif low.startswith("basic "):
        # EST clients use HTTP Basic; the password is the app credential.
        try:
            _, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            api_key = api_key or (pw or None)
        except Exception:  # noqa: S110 - a malformed Basic header is simply no credential
            pass
    return Credential(api_key=api_key, bearer=bearer)


def actor(request: Request, p: Platform = Depends(platform)) -> Actor:
    a = p.authenticate_request(_credential(request))
    if a is None:
        raise HTTPException(401, "missing or invalid credential",
                            headers={"WWW-Authenticate": 'Bearer, Basic realm="certadillo"'})
    return a
