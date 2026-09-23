from __future__ import annotations

import base64

from fastapi import Depends, HTTPException, Request

from certadillo.runtime import get_runtime
from certadillo.services import Actor, Platform


def platform():
    with get_runtime().platform() as p:
        yield p


def _raw_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    if auth.lower().startswith("basic "):
        # EST clients use HTTP Basic; the password is the app credential.
        try:
            _, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            return pw or None
        except Exception:
            return None
    return None


def actor(request: Request, p: Platform = Depends(platform)) -> Actor:
    a = p.authenticate(_raw_key(request))
    if a is None:
        raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": 'Basic realm="certadillo"'})
    return a
