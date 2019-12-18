import os
from functools import lru_cache
from typing import Dict, List, Optional

from pydantic import validator

from fastapi_auth.fastapi_util.settings.base_api_settings import BaseAPISettings
from fastapi_auth.security.password import BCryptPasswordHasher, PasswordChecker

DEFAULT_PASSWORD_CHECKER = PasswordChecker([BCryptPasswordHasher()])


class AuthSettings(BaseAPISettings):
    secret_key: bytes = os.urandom(32)
    superuser_scope: str = "admin"
    expected_scopes: Dict[str, str] = {"admin": "Admin access."}

    first_superuser: Optional[str]
    first_superuser_password: Optional[str]

    users_open_registration: bool = False
    token_url = "/token"
    refresh_url = "/token/refresh"
    api_prefix: str = "/api/v1"

    access_token_expire_seconds: int = 60 * 60 * 24 * 1  # 60 seconds * 60 minutes * 24 hours * 1 days = 1 days
    refresh_token_expire_seconds: int = 60 * 60 * 24 * 10  # 60 seconds * 60 minutes * 24 hours * 10 days = 10 days
    refresh_token_cleanup_interval_seconds: int = 60 * 60  # 60 seconds * 60 minutes
    include_expires_in_with_tokens: bool = True
    encoding_algorithm: str = "HS256"
    decoding_algorithms: List[str] = ["HS256"]

    password_checker: PasswordChecker = None  # type: ignore

    @validator("password_checker", pre=True, always=True)
    def validate_password_checker(cls, v: Optional[PasswordChecker]) -> PasswordChecker:
        if v is None:
            v = DEFAULT_PASSWORD_CHECKER
        return v

    class Config:
        env_prefix = "auth_"


@lru_cache()
def get_auth_settings() -> AuthSettings:
    return AuthSettings()
