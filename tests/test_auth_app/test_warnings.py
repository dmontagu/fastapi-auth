import logging

import pytest
from _pytest.logging import LogCaptureFixture
from _pytest.monkeypatch import MonkeyPatch

from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.util.cache import clear_caches
from tests.test_auth_app.build_app import get_test_app


@pytest.fixture
def disable_superuser_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("API_INCLUDE_ADMIN_ROUTES", "1")
    monkeypatch.setenv("API_DISABLE_SUPERUSER_DEPENDENCY", "1")
    clear_caches()


def test_superuser_warning(disable_superuser_environment: None, caplog: LogCaptureFixture) -> None:
    get_test_app()
    print(get_api_settings().include_admin_routes)
    print(get_api_settings().disable_superuser_dependency)
    assert len(caplog.record_tuples) == 1
    name, level, message = caplog.record_tuples[0]
    assert name == "fastapi_auth.dependencies"
    assert level == logging.WARNING
    assert message == "*** require_superuser is DISABLED ***"
