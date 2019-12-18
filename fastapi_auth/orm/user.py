from typing import TYPE_CHECKING, ClassVar

import sqlalchemy as sa
from sqlalchemy.ext.declarative.api import declared_attr

from fastapi_auth.fastapi_util.orm.base import Base
from fastapi_auth.fastapi_util.orm.columns import pk_column
from fastapi_auth.models.user import UserID


class UserMixin:
    if TYPE_CHECKING:
        user_id: ClassVar["sa.Column[UserID]"]
    else:

        @declared_attr
        def user_id(cls) -> "sa.Column[UserID]":
            return pk_column(id_type=UserID)

    username = sa.Column(sa.String, nullable=False, unique=True, index=True)
    hashed_password = sa.Column(sa.String, nullable=False)
    is_superuser = sa.Column(sa.Boolean, nullable=False)


if TYPE_CHECKING:

    class BaseUser(Base, UserMixin):
        pass


else:

    BaseUser = UserMixin
