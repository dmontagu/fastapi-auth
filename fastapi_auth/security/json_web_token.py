from datetime import timedelta
from typing import List
from uuid import uuid4

from fastapi.encoders import jsonable_encoder
from jwt import PyJWTError

from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.models.auth import Token, TokenPair, TokenPayload
from fastapi_auth.models.user import UserID
from fastapi_auth.security.signing import generate_signed_encoding, get_expiration_claim, parse_signed_encoding
from fastapi_auth.util.errors import expected_auth_error, raise_auth_error, raise_permissions_error


def get_validated_token(scopes: List[str], encoded: str) -> Token:
    with expected_auth_error(PyJWTError, detail="Invalid token"):
        token = _decode_token(encoded)

    for scope in scopes:
        if scope not in token.payload.scopes:
            raise_permissions_error()

    return token


def generate_tokens(*, user_id: UserID, is_superuser: bool, scopes: List[str]) -> TokenPair:
    auth_settings = get_auth_settings()
    expected_scopes = auth_settings.expected_scopes
    for scope in scopes:
        if scope not in expected_scopes:
            raise_auth_error(detail=f"Unrecognized scope: {scope!r}")

    if auth_settings.superuser_scope in scopes and not is_superuser:
        raise_permissions_error()

    expires_in = auth_settings.access_token_expire_seconds
    access = _generate_token(user_id=user_id, expires_delta=timedelta(seconds=expires_in), scopes=scopes)
    refresh = _generate_token(
        user_id=user_id, expires_delta=timedelta(seconds=auth_settings.refresh_token_expire_seconds), scopes=scopes
    )
    if auth_settings.include_expires_in_with_tokens:
        return TokenPair(access=access, refresh=refresh, expires_in=expires_in)
    else:
        return TokenPair(access=access, refresh=refresh)


def _decode_token(encoded: str) -> Token:
    payload = parse_signed_encoding(encoded)
    return Token(encoded=encoded, payload=TokenPayload(**payload))


def _generate_token(*, user_id: UserID, expires_delta: timedelta, scopes: List[str]) -> Token:
    expiration_claim = get_expiration_claim(expires_delta)
    exp = expiration_claim.exp
    token_payload = TokenPayload(sub=user_id, exp=exp, jti=uuid4(), scopes=scopes)
    claims = jsonable_encoder(token_payload)
    encoded = generate_signed_encoding(claims, expires_delta=expires_delta)
    return Token(encoded=encoded, payload=token_payload)
