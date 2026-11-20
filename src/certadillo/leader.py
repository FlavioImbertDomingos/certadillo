"""Leader election for background work.

Every replica runs the same background loops (housekeeping every
CERTADILLO_ALERT_INTERVAL_SECONDS, audit shipping every few seconds). Without
coordination, three replicas would sign three CRLs per cycle, send every alert
three times and ship each audit record three times. Each loop therefore asks
for a lease first and does the work only while it holds one.

A lease is a row in the `leases` table with a holder and an expiry. Taking or
renewing it is one conditional UPDATE (or an INSERT for a task nobody has held
yet), so it works the same on PostgreSQL, Oracle and SQLite and needs no extra
grants. The holder renews on every cycle; if it dies, another replica takes
over once the lease expires (three cycles by default). `release()` on a clean
shutdown hands it over at once.
"""
from __future__ import annotations

import os
import secrets
import socket
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from certadillo.db import Lease, as_utc, get_session

# this process, for as long as it runs
IDENTITY = f"{socket.gethostname()[:80]}:{os.getpid()}:{secrets.token_hex(3)}"
_held: dict[str, str] = {}  # task -> holder, for the leases this process believes it holds


def acquire(name: str, ttl_seconds: int, holder: str = IDENTITY, now: datetime | None = None) -> bool:
    """Take or renew the lease for `name`. True while this process holds it."""
    now = now or datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)
    with get_session() as s:
        res = s.execute(
            update(Lease)
            .where(Lease.name == name, (Lease.holder == holder) | (Lease.expires_at < now))
            .values(holder=holder, expires_at=expires)
            .execution_options(synchronize_session=False))
        if res.rowcount == 1:
            s.commit()
            _mark_acquired(name, holder, now)
            return True
        if s.get(Lease, name) is not None:
            s.rollback()
            _held.pop(name, None)
            return False
        try:  # nobody has ever held it
            s.add(Lease(name=name, holder=holder, acquired_at=now, expires_at=expires))
            s.commit()
        except IntegrityError:  # another replica inserted it first
            s.rollback()
            _held.pop(name, None)
            return False
    _mark_acquired(name, holder, now)
    return True



def _mark_acquired(name: str, holder: str, now: datetime) -> None:
    """Record when this holder took over, so `status()` shows how long the
    current leader has held the lease rather than when the row was created."""
    if _held.get(name) == holder:
        return
    _held[name] = holder
    with get_session() as s:
        s.execute(update(Lease).where(Lease.name == name, Lease.holder == holder).values(acquired_at=now)
                  .execution_options(synchronize_session=False))
        s.commit()


def release(name: str, holder: str = IDENTITY) -> None:
    """Hand the lease over now instead of letting it expire."""
    _held.pop(name, None)
    with get_session() as s:
        s.execute(update(Lease).where(Lease.name == name, Lease.holder == holder)
                  .values(expires_at=datetime(1970, 1, 1, tzinfo=timezone.utc))
                  .execution_options(synchronize_session=False))
        s.commit()


def status(now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    with get_session() as s:
        return [{"task": r.name, "holder": r.holder, "this_replica": r.holder == IDENTITY,
                 "since": as_utc(r.acquired_at).isoformat(), "expires_at": as_utc(r.expires_at).isoformat(),
                 "expired": as_utc(r.expires_at) < now}
                for r in s.query(Lease).order_by(Lease.name).all()]
