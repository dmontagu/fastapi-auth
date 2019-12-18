from calendar import timegm
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from pydantic import BaseModel

from fastapi_auth.auth_settings import get_auth_settings


class ExpirationClaim(BaseModel):
    exp: int


def get_expiration_claim(expires_delta: timedelta) -> ExpirationClaim:
    expire = datetime.utcnow() + expires_delta
    expire_int = timegm(expire.utctimetuple())
    return ExpirationClaim(exp=expire_int)


def generate_signed_encoding(claims: Dict[str, Any], expires_delta: Optional[timedelta]) -> str:
    expiration_claim: Dict[str, int] = {} if expires_delta is None else get_expiration_claim(expires_delta).dict()
    claims.update(expiration_claim)
    auth_settings = get_auth_settings()
    encoded = jwt.encode(claims, auth_settings.secret_key, algorithm=auth_settings.encoding_algorithm)
    return encoded.decode()


def parse_signed_encoding(encoded: str) -> Dict[str, Any]:
    auth_settings = get_auth_settings()
    return jwt.decode(encoded, auth_settings.secret_key, verify=True, algorithms=auth_settings.decoding_algorithms)
