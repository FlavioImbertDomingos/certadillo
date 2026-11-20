"""Leader election for background work, and the PKCS#11 session pool."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from certadillo import leader
from certadillo.crypto.signers import SessionPool
from conftest import ADMIN

T0 = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def test_one_replica_holds_a_task_until_its_lease_expires(client):
    assert leader.acquire("housekeeping", 900, holder="replica-a", now=T0)
    assert not leader.acquire("housekeeping", 900, holder="replica-b", now=T0 + timedelta(seconds=10))
    # the holder renews every cycle and keeps it
    assert leader.acquire("housekeeping", 900, holder="replica-a", now=T0 + timedelta(seconds=300))
    assert not leader.acquire("housekeeping", 900, holder="replica-b", now=T0 + timedelta(seconds=1000))
    # replica-a stops renewing (crashed): replica-b takes over after the lease runs out
    assert leader.acquire("housekeeping", 900, holder="replica-b", now=T0 + timedelta(seconds=1201))
    assert not leader.acquire("housekeeping", 900, holder="replica-a", now=T0 + timedelta(seconds=1210))
    # tasks are independent
    assert leader.acquire("audit-shipping", 45, holder="replica-a", now=T0 + timedelta(seconds=1210))


def test_release_hands_over_at_once(client):
    assert leader.acquire("housekeeping", 900, holder="replica-a", now=T0)
    leader.release("housekeeping", holder="replica-a")
    assert leader.acquire("housekeeping", 900, holder="replica-b", now=T0 + timedelta(seconds=1))
    leader.release("housekeeping", holder="replica-a")  # not the holder: changes nothing
    assert not leader.acquire("housekeeping", 900, holder="replica-c", now=T0 + timedelta(seconds=2))


def test_only_the_leader_runs_housekeeping(client):
    from certadillo.api.app import run_if_leader

    ran = []
    leader.acquire("housekeeping", 900, holder="another-replica")
    assert not run_if_leader("housekeeping", 300, lambda: ran.append(1)) and ran == []
    leader.release("housekeeping", holder="another-replica")
    assert run_if_leader("housekeeping", 300, lambda: ran.append(1)) and ran == [1]
    st = client.get("/api/v1/leaders", headers=ADMIN).json()
    row = next(r for r in st["leases"] if r["task"] == "housekeeping")
    assert row["this_replica"] and row["holder"] == st["this_replica"] == leader.IDENTITY
    assert 'certadillo_leader{task="housekeeping"} 1.0' in client.get("/metrics").text


def test_racing_replicas_get_exactly_one_leader(client):
    winners = []
    barrier = threading.Barrier(8)

    def race(i):
        barrier.wait()
        if leader.acquire("race", 60, holder=f"r{i}"):
            winners.append(i)

    threads = [threading.Thread(target=race, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1


# ------------------------------------------------------------------ PKCS#11 session pool
class SessionHandleInvalid(Exception):
    """Named like python-pkcs11's exception, which the pool recognises by name."""


class FakeSession:
    def __init__(self, n):
        self.n, self.closed = n, False

    def close(self):
        self.closed = True


def test_pool_reuses_sessions_and_caps_them():
    opened = []
    pool = SessionPool(lambda: opened.append(FakeSession(len(opened))) or opened[-1], size=2, wait_seconds=0.2)
    for _ in range(5):
        with pool.session() as s:
            assert s is opened[0]
    assert len(opened) == 1  # one caller at a time needs one session
    with pool.session() as a, pool.session() as b:
        assert a is not b and len(opened) == 2
        with pytest.raises(RuntimeError, match="no free HSM session"):
            with pool.session():
                pass


def test_pool_drops_a_broken_session_and_keeps_others():
    opened = []
    pool = SessionPool(lambda: opened.append(FakeSession(len(opened))) or opened[-1], size=2)
    with pytest.raises(SessionHandleInvalid):
        with pool.session():
            raise SessionHandleInvalid()
    assert opened[0].closed and pool.discarded == 1 and pool.created == 0
    with pytest.raises(ValueError):  # an ordinary error leaves the session usable
        with pool.session():
            raise ValueError("bad mechanism")
    with pool.session() as s:
        assert s is opened[1] and not s.closed


def test_hsm_signing_reuses_one_session_across_threads(tmp_path, softhsm):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from certadillo.crypto.signers import Pkcs11KeyStore

    store = Pkcs11KeyStore(softhsm, "certadillo", "1234")
    signer = store.generate("pool-test", "ec-p256")
    errors, sigs = [], []

    def work():
        try:
            for i in range(10):
                sig = signer.sign(f"msg-{i}".encode(), hashes.SHA256())
                signer.public_key().verify(sig, f"msg-{i}".encode(), ec.ECDSA(hashes.SHA256()))
                sigs.append(sig)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and len(sigs) == 80
    assert store.pool.created == 1  # one logged-in session, reused for every signature
    store.pool.close()
