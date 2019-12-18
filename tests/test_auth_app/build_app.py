from pathlib import Path
from typing import Iterator, Optional

from fastapi import FastAPI

from fastapi_auth.auth_app import get_auth_app
from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.fastapi_util.setup.initialize import get_configured_metadata, initialize_database
from fastapi_auth.fastapi_util.setup.setup_api import setup_openapi
from fastapi_auth.fastapi_util.util.session import get_engine
from tests.util.custom_user import AuthRouterBuilder


def get_test_app(include_admin_routes: Optional[bool] = None, openapi_url: Optional[str] = "/openapi.json") -> FastAPI:
    include_admin_routes = include_admin_routes or get_api_settings().include_admin_routes
    auth_settings = get_auth_settings()
    router_builder = AuthRouterBuilder(auth_settings)
    app = get_auth_app(router_builder, include_admin_routes, openapi_url=openapi_url)
    setup_openapi(app)
    return app


def get_test_app_fixture(include_admin_routes: Optional[bool] = None) -> Iterator[FastAPI]:
    test_db_path = Path("./test.db")
    if test_db_path.exists():
        test_db_path.unlink()
    app = get_test_app(include_admin_routes=include_admin_routes)

    engine = get_engine()
    metadata = get_configured_metadata(app)
    metadata.create_all(bind=engine)
    initialize_database(engine)

    auth_settings = get_auth_settings()
    AuthRouterBuilder(auth_settings).setup_first_superuser(engine)

    yield app
    if test_db_path.exists():
        test_db_path.unlink()
