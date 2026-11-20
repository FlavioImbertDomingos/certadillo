"""Alembic migrations: fresh databases, databases made before migrations
existed, and the migrations kept in step with the model.

Set CERTADILLO_TEST_PG_URL (and CERTADILLO_TEST_ORACLE_URL) to run the
model-versus-migrations check against a real server too, as CI does."""
from __future__ import annotations

import os
import sqlite3

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from click.testing import CliRunner
from sqlalchemy import create_engine, inspect, text

from certadillo import db

SERVER_URLS = [u for u in (os.environ.get("CERTADILLO_TEST_PG_URL"), os.environ.get("CERTADILLO_TEST_ORACLE_URL")) if u]


def _empty(url):
    engine = create_engine(url, future=True)
    if not url.startswith("sqlite"):
        db.Base.metadata.drop_all(engine)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS alembic_version") if engine.dialect.name != "oracle"
                         else text("BEGIN EXECUTE IMMEDIATE 'DROP TABLE alembic_version'; "
                                   "EXCEPTION WHEN OTHERS THEN NULL; END;"))
    return engine


def _diff(engine):
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(ctx, db.Base.metadata)


@pytest.fixture(params=["sqlite"] + SERVER_URLS)
def url(request, tmp_path):
    return f"sqlite:///{tmp_path / 'm.db'}" if request.param == "sqlite" else request.param


def test_migrations_build_exactly_the_model(url):
    """Running every migration on an empty database gives the same schema as
    the model; a model change without a migration fails here."""
    engine = _empty(url)
    cfg = db._alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    assert _diff(engine) == []
    assert db.schema_status(engine)["up_to_date"]


def test_fresh_database_is_created_and_stamped(url):
    engine = _empty(url)
    out = db.migrate(engine)
    assert out["action"] == "created" and out["from"] is None and out["to"] == db.schema_status(engine)["head"]
    assert _diff(engine) == []
    assert db.migrate(engine)["action"] == "upgraded"  # a second start changes nothing


def test_database_made_before_migrations_is_adopted(tmp_path):
    """A 0.1 database: some tables, some missing nullable columns, real rows.
    It keeps its rows, gains what it lacked, and is stamped."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE teams (id INTEGER PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, "
                "contact_email VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL)")
    con.execute("INSERT INTO teams VALUES (1, 'payments', 'p@bank.example', '2026-01-01 00:00:00')")
    con.commit()
    con.close()
    engine = create_engine(f"sqlite:///{path}", future=True)
    out = db.migrate(engine)
    assert out["action"].startswith("adopted") and out["from"] is None
    cols = {c["name"] for c in inspect(engine).get_columns("teams")}
    assert {"chat_channel", "webhook_enc", "cost_center"} <= cols
    assert inspect(engine).has_table("audit_events")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT name FROM teams")).scalar() == "payments"
    assert db.schema_status(engine)["up_to_date"]


def test_auto_migrate_off_refuses_a_stale_schema(tmp_path):
    path = tmp_path / "stale.db"
    sqlite3.connect(path).execute("CREATE TABLE teams (id INTEGER PRIMARY KEY)").connection.close()
    with pytest.raises(RuntimeError, match="certadillo db migrate"):
        db.init_db(f"sqlite:///{path}", auto_migrate=False)


def test_cli_migrate_and_status(tmp_path, monkeypatch):
    from certadillo import cli, config

    monkeypatch.setenv("CERTADILLO_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERTADILLO_DB_URL", f"sqlite:///{tmp_path / 'c.db'}")
    monkeypatch.setattr(config, "_settings", None)
    run = CliRunner()
    assert run.invoke(cli.main, ["db", "status"]).exit_code == 1  # nothing there yet
    r = run.invoke(cli.main, ["db", "migrate"])
    assert r.exit_code == 0, r.output
    assert '"action": "created"' in r.output and "sqlite triggers" in r.output
    r = run.invoke(cli.main, ["db", "status"])
    assert r.exit_code == 0 and '"up_to_date": true' in r.output
