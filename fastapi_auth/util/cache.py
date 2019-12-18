from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.fastapi_util.settings.database_settings import get_database_settings
from fastapi_auth.fastapi_util.util.session import get_engine, get_sessionmaker


def clear_caches() -> None:
    get_api_settings.cache_clear()
    get_database_settings.cache_clear()
    get_auth_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
