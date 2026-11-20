"""Per-principal rate limits.

Two limits, both token buckets kept in memory on each replica:

- Requests: every authenticated API call counts against its principal, with
  a rate per role (CERTADILLO_RATE_LIMITS, e.g. "app=600/m;operator=1200/m").
  A runaway script or a stolen key cannot swamp the API for everyone else.
- Issuance: every certificate request counts against its app, whatever the
  protocol (REST, ACME, EST, SCEP, CMP), at CERTADILLO_ISSUANCE_LIMIT
  ("500/h" by default). A stolen app credential cannot mint thousands of
  certificates before someone notices; the RateLimited alert fires on the
  first refusal.

The bucket holds a full period's allowance, so a burst up to the limit is
fine and the allowance refills steadily. With N replicas behind a load
balancer the effective limit is up to N times the setting.
"""
from __future__ import annotations

import re
import threading
import time

DEFAULT_REQUEST_LIMITS = {"app": "600/m", "agent": "600/m", "gateway": "1200/m", "admin": "1200/m",
                          "operator": "1200/m", "approver": "1200/m", "auditor": "1200/m"}
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class RateLimited(Exception):
    def __init__(self, message: str, retry_after: int):
        super().__init__(message)
        self.retry_after = retry_after


def parse(spec: str | None) -> tuple[int, int] | None:
    """'600/m' -> (600, 60). '0', '' or 'off' -> None (no limit)."""
    spec = (spec or "").strip().lower()
    if spec in ("", "0", "off", "none"):
        return None
    m = re.fullmatch(r"(\d+)\s*/\s*(\d*)\s*([smhd])", spec)
    if not m:
        raise ValueError(f"rate limit {spec!r} must look like 600/m, 500/h or 10/30s")
    count, mult, unit = int(m.group(1)), int(m.group(2) or 1), m.group(3)
    return (count, mult * _UNITS[unit]) if count else None


class Limiter:
    def __init__(self, clock=time.monotonic):
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def hit(self, key: str, count: int, period: int) -> float | None:
        """Take one token for key. None when allowed, else seconds until one is free."""
        rate = count / period
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(count), now))
            tokens = min(float(count), tokens + (now - last) * rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                return None
            self._buckets[key] = (tokens, now)
            return (1 - tokens) / rate

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


LIMITER = Limiter()


def _enforce(limit: str, key: str, spec: str | None, role: str, what: str) -> None:
    from certadillo.observability.metrics import RATE_LIMITED

    parsed = parse(spec)
    if parsed is None:
        return
    wait = LIMITER.hit(f"{limit}:{key}", *parsed)
    if wait is not None:
        RATE_LIMITED.labels(limit=limit, role=role).inc()
        retry = max(1, int(wait + 0.999))
        raise RateLimited(f"{what} limit of {spec} reached; retry in {retry}s", retry)


def check_request(settings, principal: str, role: str) -> None:
    spec = settings.rate_limits.get(role, DEFAULT_REQUEST_LIMITS.get(role))
    _enforce("requests", principal, spec, role, f"request rate for {principal}")


def check_issuance(settings, app_name: str, role: str) -> None:
    _enforce("issuance", app_name, settings.issuance_limit, role, f"certificate issuance for app {app_name}")
