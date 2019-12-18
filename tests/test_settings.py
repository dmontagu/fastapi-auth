import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.settings.database_settings import DatabaseBackend, get_database_settings
from fastapi_auth.fastapi_util.util.session import get_engine
from fastapi_auth.security.password import BCryptPasswordHasher, PasswordChecker
from fastapi_auth.util.cache import clear_caches


@pytest.mark.parametrize("sqlalchemy_database_uri", ["sqlite:///./test.db", "sqlite:///./test2.db"])
def test_db_settings(monkeypatch: MonkeyPatch, sqlalchemy_database_uri: str) -> None:
    monkeypatch.setenv("DB_SQLALCHEMY_URI", sqlalchemy_database_uri)

    clear_caches()
    assert get_database_settings().sqlalchemy_uri == sqlalchemy_database_uri


def test_postgres_sqlalchemy_uri(monkeypatch: MonkeyPatch) -> None:
    environment = {"DB_BACKEND": "postgresql", "DB_USER": "a", "DB_PASSWORD": "b", "DB_HOST": "c", "db_db": "d"}
    for k, v in environment.items():
        monkeypatch.setenv(k, v)

    clear_caches()
    assert get_database_settings().sqlalchemy_uri == "postgresql://a:b@c/d"


@pytest.mark.parametrize(
    "sqlalchemy_database_uri,expected_backend",
    [("sqlite://", DatabaseBackend.sqlite), ("postgresql://a:b@c/d", DatabaseBackend.postgresql)],
)
def test_database_backend(
    monkeypatch: MonkeyPatch, sqlalchemy_database_uri: str, expected_backend: DatabaseBackend
) -> None:
    monkeypatch.setenv("DB_SQLALCHEMY_URI", sqlalchemy_database_uri)
    clear_caches()
    engine = get_engine()
    assert DatabaseBackend.from_engine(engine) == expected_backend


def test_auth_settings() -> None:
    default_checker = get_auth_settings().password_checker
    new_checker = PasswordChecker([BCryptPasswordHasher()])
    assert default_checker is not new_checker
    get_auth_settings().password_checker = new_checker

    assert get_auth_settings().password_checker is not default_checker
    assert get_auth_settings().password_checker is new_checker

    with pytest.raises(ValidationError) as exc_info:
        get_auth_settings().password_checker = 1  # type: ignore[assignment]
    assert exc_info.value.errors() == [
        {
            "ctx": {"expected_arbitrary_type": "PasswordChecker"},
            "loc": ("password_checker",),
            "msg": "instance of PasswordChecker expected",
            "type": "type_error.arbitrary_type",
        }
    ]
