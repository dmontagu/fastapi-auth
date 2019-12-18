from typing import Optional

import sqlalchemy as sa
from pydantic import EmailStr

from fastapi_auth.auth_app import BaseAuthRouterBuilder
from fastapi_auth.fastapi_util.api_model import APIModel
from fastapi_auth.fastapi_util.orm.base import Base
from fastapi_auth.models.user import (
    UserBaseInDB as BaseUserModel,
    UserCreate as BaseUserCreate,
    UserCreateRequest as BaseUserCreateRequest,
    UserInDB as BaseUserInDB,
    UserUpdate as BaseUserUpdate,
)
from fastapi_auth.orm.user import BaseUser


# Pydantic Models
class ExtraUserAttributes(APIModel):
    email: Optional[EmailStr]


class UserCreate(BaseUserCreate, ExtraUserAttributes):
    pass


class UserCreateRequest(BaseUserCreateRequest, ExtraUserAttributes):
    pass


class UserInDB(BaseUserInDB, ExtraUserAttributes):
    pass


class UserUpdate(BaseUserUpdate, ExtraUserAttributes):
    pass


class UserResult(BaseUserModel, ExtraUserAttributes):
    pass


# Sqlalchemy Model
class User(BaseUser, Base):
    email = sa.Column(sa.String)


class AuthRouterBuilder(BaseAuthRouterBuilder[UserCreate, UserCreateRequest, UserInDB, UserUpdate, UserResult, User]):
    create_type = UserCreate
    create_request_type = UserCreateRequest
    in_db_type = UserInDB
    update_type = UserUpdate
    api_type = UserResult
    orm_type = User
