from functools import lru_cache
from typing import Any, Dict

from fastapi_auth.fastapi_util.settings.base_api_settings import BaseAPISettings


class APISettings(BaseAPISettings):
    # fastapi.applications.FastAPI initializer kwargs
    debug: bool = False
    docs_url: str = "/docs"
    openapi_prefix: str = ""
    openapi_url: str = "/openapi.json"
    redoc_url: str = "/redoc"
    title: str = "Fast API"
    version: str = "0.1.0"

    # Custom settings
    disable_docs: bool = False
    disable_superuser_dependency: bool = False
    include_admin_routes: bool = False
    main_router_prefix: str = "/api/v1"

    @property
    def fastapi_kwargs(self) -> Dict[str, Any]:
        fastapi_kwargs: Dict[str, Any] = {
            "debug": self.debug,
            "docs_url": self.docs_url,
            "openapi_prefix": self.openapi_prefix,
            "openapi_url": self.openapi_url,
            "redoc_url": self.redoc_url,
            "title": self.title,
            "version": self.version,
        }
        if self.disable_docs:
            fastapi_kwargs.update({"docs_url": None, "openapi_url": None, "redoc_url": None})
        return fastapi_kwargs

    class Config:
        env_prefix = "api_"


@lru_cache()
def get_api_settings() -> APISettings:
    return APISettings()
