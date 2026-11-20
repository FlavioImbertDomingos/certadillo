"""`certadillo db harden` on real servers: the application role can do its
job but cannot change audit history or drop the guard.

PostgreSQL: CERTADILLO_TEST_PG_URL as a role that can CREATE ROLE.
Oracle:     CERTADILLO_TEST_ORACLE_URL (the owner) and
            CERTADILLO_TEST_ORACLE_SYSTEM_URL (to create the application user)."""
from __future__ import annotations

import os
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DatabaseError

from certadillo import db
from conftest import ADMIN, issue, make_settings, onboard

PG = os.environ.get("CERTADILLO_TEST_PG_URL")
ORA = os.environ.get("CERTADILLO_TEST_ORACLE_URL")
ORA_SYS = os.environ.get("CERTADILLO_TEST_ORACLE_SYSTEM_URL")


def _fresh(url):
    engine = db.make_engine(url)
    db.drop_everything(engine)
    db.migrate(engine)
    db.install_audit_guards(engine)
    return engine


def _app_works_and_cannot_rewrite_history(tmp_path, app_url, schema=None):
    from certadillo.api.app import create_app

    s = make_settings(tmp_path, db_url=app_url, db_schema=schema, db_auto_migrate=False)
    with TestClient(create_app(s, background=False)) as c:
        _, h = onboard(c)
        issue(c, h)
        assert c.get("/api/v1/audit/verify", headers=ADMIN).json()["valid"]
    app = db.make_engine(app_url, schema)
    for stmt in ("UPDATE audit_events SET actor = 'nobody'", "DELETE FROM audit_events"):
        with pytest.raises(DatabaseError):
            with app.begin() as conn:
                conn.execute(text(stmt))
    return app


@pytest.mark.skipif(not PG, reason="needs CERTADILLO_TEST_PG_URL")
def test_postgres_app_role(tmp_path):
    owner = _fresh(PG)
    role, pw = f"cdl_app_{secrets.token_hex(3)}", secrets.token_hex(12)
    with owner.begin() as conn:
        conn.execute(text(f"CREATE ROLE {role} LOGIN PASSWORD '{pw}'"))
    out = db.harden(owner, role)
    assert out["hardened"] and out["app_role"] == role
    app_url = make_url(PG).set(username=role, password=pw).render_as_string(hide_password=False)
    app = _app_works_and_cannot_rewrite_history(tmp_path, app_url)
    with pytest.raises(DatabaseError):  # not the owner: the guard stays
        with app.begin() as conn:
            conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
    with pytest.raises(ValueError, match="owns the tables"):
        db.harden(owner, make_url(PG).username)


@pytest.mark.skipif(not (ORA and ORA_SYS), reason="needs CERTADILLO_TEST_ORACLE_URL and _SYSTEM_URL")
def test_oracle_app_user(tmp_path):
    owner = _fresh(ORA)
    user, pw = f"CDL_APP_{secrets.token_hex(3).upper()}", "App" + secrets.token_hex(10)
    sysdba = create_engine(ORA_SYS)
    with sysdba.begin() as conn:
        conn.execute(text(f'CREATE USER {user} IDENTIFIED BY "{pw}"'))
        conn.execute(text(f"GRANT CREATE SESSION TO {user}"))
    try:
        out = db.harden(owner, user.lower())
        owner_name = make_url(ORA).username.upper()
        assert out["app_role"] == user and out["next"].endswith(f"CERTADILLO_DB_SCHEMA={owner_name}")
        app_url = make_url(ORA).set(username=user, password=pw).render_as_string(hide_password=False)
        app = _app_works_and_cannot_rewrite_history(tmp_path, app_url, schema=owner_name)
        with pytest.raises(DatabaseError):  # not the owner: the guard stays
            with app.begin() as conn:
                conn.execute(text(f"ALTER TRIGGER {owner_name}.audit_events_append_only DISABLE"))
        app.dispose()
    finally:
        if db._engine is not None:
            db._engine.dispose()
        with sysdba.begin() as conn:
            conn.execute(text(f"DROP USER {user} CASCADE"))
