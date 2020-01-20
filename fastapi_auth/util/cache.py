from typing import TYPE_CHECKING

from fastapi_utils.api_settings import get_api_settings

from fastapi_auth.auth_settings import get_auth_settings


def clear_caches() -> None:
    get_api_settings.cache_clear()
    get_auth_settings.cache_clear()


if TYPE_CHECKING:
    cached_property = property
else:
    try:
        from functools import cached_property
    except ImportError:
        from cached_property import cached_property
