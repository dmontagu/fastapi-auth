from enum import auto
from functools import lru_cache
from typing import Any, Dict, Optional

import sqlalchemy as sa
from pydantic import validator

from fastapi_auth.fastapi_util.settings.base_api_settings import BaseAPISettings
from fastapi_auth.fastapi_util.util.enums import StrEnum


class DatabaseBackend(StrEnum):
    postgresql = auto()
    sqlite = auto()

    @staticmethod
    def from_engine(engine: sa.engine.Engine) -> "DatabaseBackend":
        return DatabaseBackend(engine.dialect.name)


class DatabaseSettings(BaseAPISettings):
    backend: DatabaseBackend = None  # type: ignore

    user: Optional[str]
    password: Optional[str]
    host: Optional[str]
    db: Optional[str]

    sqlalchemy_uri: str = None  # type: ignore

    log_sqlalchemy_sql_statements: bool = False

    min_size: int = 10
    max_size: int = 10
    force_rollback: bool = False

    @validator("sqlalchemy_uri", pre=True, always=True)
    def validate_sqlalchemy_uri(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if v is None:
            backend = values.get("backend")
            backend = backend.value if backend is not None else None

            user = values["user"]
            password = values["password"]
            host = values["host"]
            db = values["db"]

            v = f"{backend}://{user}:{password}@{host}/{db}"
        return v

    class Config:
        env_prefix = "db_"


@lru_cache()
def get_database_settings() -> DatabaseSettings:
    return DatabaseSettings()
