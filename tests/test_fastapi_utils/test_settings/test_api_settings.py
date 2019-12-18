import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi import FastAPI
from starlette.status import HTTP_200_OK, HTTP_404_NOT_FOUND
from starlette.testclient import TestClient

from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.util.cache import clear_caches


def get_app() -> FastAPI:
    clear_caches()
    api_settings = get_api_settings()
    return FastAPI(**api_settings.fastapi_kwargs)


@pytest.mark.parametrize("disable_docs,status_code", [("1", HTTP_404_NOT_FOUND), ("0", HTTP_200_OK)])
def test_enable_docs(monkeypatch: MonkeyPatch, disable_docs: str, status_code: int) -> None:
    monkeypatch.setenv("API_DISABLE_DOCS", disable_docs)
    app = get_app()
    response = TestClient(app).get("/docs")
    assert response.status_code == status_code
