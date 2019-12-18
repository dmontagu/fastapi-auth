import logging

from _pytest.logging import LogCaptureFixture
from fastapi import FastAPI

from fastapi_auth import auth_app
from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.util.session import get_engine
from tests.test_auth_app.build_app import AuthRouterBuilder


def test_setup_auth_idempotent(debug_auth_app: FastAPI, caplog: LogCaptureFixture) -> None:
    logger_name = auth_app.__name__
    caplog.set_level(logging.INFO, logger=logger_name)

    auth_settings = get_auth_settings()
    AuthRouterBuilder(auth_settings).setup_first_superuser(get_engine())

    name, level, message = caplog.record_tuples[-1]
    assert name == logger_name
    assert level == logging.INFO
    assert message == "First superuser already exists."
