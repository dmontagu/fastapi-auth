# FastAPI Auth

**Pluggable auth for use with [FastAPI](https://github.com/tiangolo/fastapi)**

* Supports OAuth2 Password Flow
* Uses JWT access and refresh tokens
* 100% mypy and test coverage 
* Supports custom user models (both ORM and pydantic) without sacrificing any type-safety

Usage:
------

After installing the development dependencies, the following script should run as-is:

```python
from typing import Optional

import sqlalchemy as sa
from fastapi import FastAPI
from pydantic import EmailStr

from fastapi_auth.auth_app import BaseAuthRouterBuilder
from fastapi_auth.auth_settings import get_auth_settings
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


class AuthRouterBuilder(
    BaseAuthRouterBuilder[
        UserCreate, UserCreateRequest, UserInDB, UserUpdate, UserResult, User
    ]
):
    create_type = UserCreate
    create_request_type = UserCreateRequest
    in_db_type = UserInDB
    update_type = UserUpdate
    api_type = UserResult
    orm_type = User


auth_settings = get_auth_settings()
router_builder = AuthRouterBuilder(auth_settings)

app = FastAPI()

...  # Add routes

router_builder.include_auth(app.router)
router_builder.add_expired_token_cleanup(app)

print(list(app.openapi()["paths"].keys()))
"""
[
    "/auth/token",
    "/auth/token/refresh",
    "/auth/token/validate",
    "/auth/token/logout",
    "/auth/token/logout/all",
    "/auth/register",
    "/auth/self",
    "/admin/users/{user_id}",
    "/admin/users",
]
"""
```

You can run the above app the same way you would run any other ASGI app, and see the docs at `/docs`.

* You can find a more complete example of configuring an app in `tests/test_auth_app/build_app.py`.
* Dependency functions that can be used to read the user can be found in `fastapi_auth.dependencies`
    * If you want to inject the full user model from the database, use the classmethod `AuthRouteBuilder.get_user`
* Various environment-variable-controlled settings are contained in `fastapi_auth.auth_settings`

Contributing:
-------------

Pull requests welcome!

To get started, clone the repo and run `make develop`.

### Make commands:

Run `make` from the project root to see basic command documentation

### TODO:

* Release on PyPI (please let me know if you can help with this!)
* Improve documentation, including a more representative example app using dependencies, etc.
* Refactor `fastapi_auth.fastapi_utils` into a stand-alone package
* Consider replacing the use of `sqlalchemy`'s ORM with `encode/databases`
