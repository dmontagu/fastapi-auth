import sqlalchemy as sa
from fastapi import FastAPI

from fastapi_auth.fastapi_util.orm.base import Base
from fastapi_auth.fastapi_util.setup.setup_database import setup_database, setup_database_metadata
from fastapi_auth.fastapi_util.util.session import get_engine


def initialize_database(engine: sa.engine.Engine) -> None:
    setup_database(engine)


def get_configured_metadata(_app: FastAPI) -> sa.MetaData:
    """
    This function accepts the app instance as an argument purely as a check to ensure that all resources
    the app depends on have been imported.

    In particular, this ensures the sqlalchemy metadata is populated.
    """
    engine = get_engine()
    setup_database(engine)
    setup_database_metadata(Base.metadata, engine)
    return Base.metadata
