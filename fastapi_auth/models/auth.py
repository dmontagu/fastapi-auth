from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel

from fastapi_auth.models.user import JWTUser, UserID
from fastapi_auth.security.password import RawPassword


class TokenPayload(BaseModel):
    sub: UserID
    exp: int
    jti: UUID
    scopes: List[str] = []


class Token(BaseModel):
    encoded: str
    payload: TokenPayload

    def jwt_user(self) -> JWTUser:
        return JWTUser(user_id=self.payload.sub, scopes=self.payload.scopes)


class TokenPair(BaseModel):
    access: Token
    refresh: Token
    expires_in: Optional[int]

    def to_response(self) -> "AuthTokens":
        tokens = AuthTokens(access_token=self.access.encoded, refresh_token=self.refresh.encoded, token_type="bearer")
        if self.expires_in is not None:
            tokens.expires_in = self.expires_in
        return tokens


class AuthTokens(BaseModel):
    """
    *Must* inherit from BaseModel (and thus use underscores) to comply with OAuth 2.0 standard
    """

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: Optional[int]


class AuthRegistrationRequest(BaseModel):
    username: str
    password: RawPassword
