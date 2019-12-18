import sqlalchemy as sa

from fastapi_auth.fastapi_util.orm.guid_type import GUID
from fastapi_auth.fastapi_util.settings.database_settings import DatabaseBackend


def setup_database(engine: sa.engine.Engine) -> None:
    setup_guids(engine)


def setup_guids(engine: sa.engine.Engine) -> None:
    """
    Set up UUID generation using the uuid-ossp extension for postgres
    """
    database_backend = DatabaseBackend.from_engine(engine)
    # TODO: Add some way to run postgres-specific tests
    if database_backend == DatabaseBackend.postgresql:  # pragma: no cover
        # noinspection SqlDialectInspection,SqlNoDataSourceInspection
        uuid_generation_setup_query = 'create EXTENSION if not EXISTS "pgcrypto"'
        engine.execute(uuid_generation_setup_query)


def setup_database_metadata(metadata: sa.MetaData, engine: sa.engine.Engine) -> None:
    setup_guid_server_defaults(metadata, engine)


def setup_guid_server_defaults(metadata: sa.MetaData, engine: sa.engine.Engine) -> None:
    database_backend = DatabaseBackend.from_engine(engine)

    guid_server_defaults = {
        DatabaseBackend.postgresql: "gen_random_uuid()",
        DatabaseBackend.sqlite: "(lower(hex(randomblob(16))))",
    }
    for table in metadata.tables.values():
        if len(table.primary_key.columns) != 1:
            continue
        for column in table.primary_key.columns:
            if type(column.type) is GUID:
                column.server_default = sa.DefaultClause(sa.text(guid_server_defaults[database_backend]))
