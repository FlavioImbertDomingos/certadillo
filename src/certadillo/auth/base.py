"""The authenticator seam.

Every request's credential passes through an ordered list of authenticators.
The API-key store and the OIDC token validator are interchangeable
implementations, so an organization can run keys, an external IdP, or both side
by side during a migration. Each authenticator returns an Actor or None; the
first to return an Actor wins, and None everywhere means 401.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class Credential:
    """What the request presented. api_key is the X-API-Key (or a cdl_ bearer /
    Basic password); bearer is a JWT-shaped bearer token."""

    api_key: str | None = None
    bearer: str | None = None


class Authenticator(Protocol):
    name: str

    def authenticate(self, cred: Credential, platform) -> object | None:
        """Return an Actor, or None to pass to the next authenticator."""
        ...


class ApiKeyAuthenticator:
    """The built-in credential store: a hashed API key mapped to a Principal."""

    name = "api_key"

    def authenticate(self, cred: Credential, platform):
        key = cred.api_key or (cred.bearer if cred.bearer and cred.bearer.startswith("cdl_") else None)
        if not key:
            return None
        return platform.authenticate(key)


class OidcAuthenticator:
    """Validates a JWT bearer token from an external IdP and synthesizes an
    Actor from its claims. No Principal row is looked up or created."""

    name = "oidc"

    def __init__(self, validator):
        self.validator = validator

    def authenticate(self, cred: Credential, platform):
        from certadillo.auth.oidc import TokenError

        if not cred.bearer:
            return None
        try:
            claims = self.validator.validate(cred.bearer)
        except TokenError as exc:
            platform.note_auth_failure("oidc", str(exc))
            return None
        role = self.validator.role_for(claims)
        if role is None:
            platform.note_auth_failure("oidc", "token carries no role that maps to access here")
            return None
        return platform.actor_from_token(self.validator.username(claims), role, self.validator.app_ref(claims))
