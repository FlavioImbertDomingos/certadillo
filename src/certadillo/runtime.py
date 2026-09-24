"""Process-wide wiring: settings, database, key store, policies, bootstrap."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass

from certadillo import db
from certadillo.config import Settings, get_settings
from certadillo.crypto.signers import build_keystore
from certadillo.db import CertificateAuthority, Principal
from certadillo.observability.metrics import register_inventory_collector
from certadillo.policy.engine import load_policies
from certadillo.services import Platform, hash_key

log = logging.getLogger("certadillo")


@dataclass
class Runtime:
    settings: Settings
    policies: dict
    keystore: object

    @contextmanager
    def platform(self):
        session = db.get_session()
        try:
            yield Platform(session, self.settings, self.policies, self.keystore)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


_rt: Runtime | None = None


def init_runtime(settings: Settings | None = None) -> Runtime:
    global _rt
    settings = settings or get_settings()
    db.init_db(settings.db_url)
    from certadillo import integrity

    integrity.configure(settings)
    rt = Runtime(settings=settings, policies=load_policies(settings.policy_file), keystore=build_keystore(settings))
    register_inventory_collector(db.get_session)
    bootstrap(rt)
    _rt = rt
    return rt


def get_runtime() -> Runtime:
    if _rt is None:
        return init_runtime()
    return _rt


def bootstrap(rt: Runtime) -> None:
    from certadillo import integrity
    from certadillo.crypto.fieldcipher import backfill_encrypted_fields

    with rt.platform() as p:
        s = p.s
        # once per deployment: seal rows written before sealing existed, then enforce
        integrity.backfill(s, rt.settings)
        backfill_encrypted_fields(p)
        for raw, name, role in (
            (rt.settings.bootstrap_admin_key, "bootstrap-admin", "admin"),
            (rt.settings.bootstrap_approver_key, "bootstrap-approver", "approver"),
        ):
            if raw and not s.query(Principal).filter_by(key_hash=hash_key(raw)).first():
                p.create_principal(None, name, role, raw_key=raw)
        if rt.settings.auto_init_ca and not s.query(CertificateAuthority).first():
            init_hierarchy(p)


def init_hierarchy(p: Platform) -> None:
    from certadillo.audit.log import record

    root = p.ca.create_root("root-ca")
    issuing = p.ca.create_subordinate(root, "issuing-ca-1")
    p.ca.generate_crl(root, next_update_hours=24 * 30)
    p.ca.generate_crl(issuing)
    record(p.s, "system", "ca.init", "root-ca", {"issuing": issuing.name, "signer": issuing.signer_type})
    log.info("CA hierarchy created", extra={"root": root.subject, "issuing": issuing.subject})
