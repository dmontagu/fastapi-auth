from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_auth.models.user import UserID
from fastapi_auth.security.json_web_token import _generate_token, get_validated_token


def test_jwt_fail() -> None:
    user_id = UserID(uuid4())
    token = _generate_token(user_id=user_id, expires_delta=timedelta(seconds=-1), scopes=[])
    with pytest.raises(HTTPException) as exc_info:
        get_validated_token(scopes=[], encoded=token.encoded)
    assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Invalid token"


def test_jwt_success() -> None:
    user_id = UserID(uuid4())
    token = _generate_token(user_id=user_id, expires_delta=timedelta(seconds=1), scopes=[])
    validated_token = get_validated_token(scopes=[], encoded=token.encoded)
    assert validated_token.encoded == token.encoded
