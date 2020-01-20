import uuid
from typing import List, NewType, Optional

from fastapi_utils.api_model import APIModel
from pydantic import BaseModel

from fastapi_auth.security.password import HashedPassword, RawPassword

UserID = NewType("UserID", uuid.UUID)


class JWTUser(BaseModel):
    user_id: UserID
    scopes: List[str] = []


class UserModelBase(APIModel):
    username: str


class UserBaseInDB(UserModelBase):
    user_id: UserID


class UserCreate(UserModelBase):
    hashed_password: HashedPassword
    is_superuser: bool


class UserCreateRequest(UserModelBase):
    password: RawPassword


class UserInDB(UserCreate):
    user_id: UserID


class UserUpdate(APIModel):
    username: Optional[str]
    password: Optional[RawPassword]
