"""Alembic environment. Certadillo runs migrations itself (`certadillo db
migrate`, or at start-up unless CERTADILLO_DB_AUTO_MIGRATE=false), passing the
connection in; the alembic.ini at the repository root is only for writing
new revisions."""
from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from certadillo.db import Base, autogenerate_filter

target_metadata = Base.metadata


def _configure(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite alters tables by copying them
        compare_type=True,
        include_object=autogenerate_filter(connection.dialect.name),
        version_table_schema=context.config.attributes.get("version_table_schema"),
    )


connection = context.config.attributes.get("connection")
if connection is not None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()
else:  # `alembic revision --autogenerate` from a developer checkout
    engine = engine_from_config(context.config.get_section(context.config.config_ini_section, {}),
                                prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as conn:
        _configure(conn)
        with context.begin_transaction():
            context.run_migrations()
