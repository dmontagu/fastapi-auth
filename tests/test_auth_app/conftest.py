from typing import Iterator

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi import FastAPI

from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.security.password import RawPassword
from fastapi_auth.util.cache import clear_caches
from tests.test_auth_app.build_app import get_test_app_fixture

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = RawPassword("admin_password")


@pytest.fixture(scope="module")
def monkeypatch_module() -> Iterator[MonkeyPatch]:
    m = MonkeyPatch()
    yield m
    m.undo()


@pytest.fixture(scope="module")
def debug_environment(monkeypatch_module: MonkeyPatch) -> None:
    """
    Not necessarily reflective of a debug environment.
    Just makes it easier to test multiple environment settings.
    """

    monkeypatch_module.setenv("API_DEBUG", "1")
    monkeypatch_module.setenv("API_INCLUDE_ADMIN_ROUTES", "1")

    monkeypatch_module.setenv("DB_BACKEND", "sqlite")
    monkeypatch_module.setenv("DB_SQLALCHEMY_URI", "sqlite:///./test.db")
    monkeypatch_module.setenv("DB_LOG_SQLALCHEMY_SQL_STATEMENTS", "0")

    monkeypatch_module.setenv("AUTH_FIRST_SUPERUSER", ADMIN_USERNAME)
    monkeypatch_module.setenv("AUTH_FIRST_SUPERUSER_PASSWORD", ADMIN_PASSWORD)
    monkeypatch_module.setenv("AUTH_INCLUDE_EXPIRES_IN_WITH_TOKENS", "false")
    monkeypatch_module.setenv("AUTH_USERS_OPEN_REGISTRATION", "true")
    clear_caches()


@pytest.fixture(scope="module")
def prod_environment(monkeypatch_module: MonkeyPatch) -> None:
    """
    Not necessarily reflective of a prod environment.
    Just makes it easier to test multiple environment settings.
    """
    monkeypatch_module.setenv("API_DEBUG", "0")
    monkeypatch_module.setenv("API_INCLUDE_ADMIN_ROUTES", "1")

    monkeypatch_module.setenv("DB_BACKEND", "sqlite")
    monkeypatch_module.setenv("DB_SQLALCHEMY_URI", "sqlite:///./test.db")
    monkeypatch_module.setenv("DB_LOG_SQLALCHEMY_SQL_STATEMENTS", "0")

    monkeypatch_module.setenv("AUTH_FIRST_SUPERUSER", ADMIN_USERNAME)
    monkeypatch_module.setenv("AUTH_FIRST_SUPERUSER_PASSWORD", ADMIN_PASSWORD)
    monkeypatch_module.setenv("AUTH_INCLUDE_EXPIRES_IN_WITH_TOKENS", "true")
    clear_caches()


@pytest.fixture(scope="module")
def debug_auth_app(debug_environment: None) -> Iterator[FastAPI]:
    assert get_auth_settings().include_expires_in_with_tokens is False
    yield from get_test_app_fixture()


@pytest.fixture(scope="module")
def prod_auth_app(prod_environment: None) -> Iterator[FastAPI]:
    assert get_auth_settings().include_expires_in_with_tokens is True
    assert get_api_settings().debug is False

    # Try re-adding the middleware
    yield from get_test_app_fixture()
