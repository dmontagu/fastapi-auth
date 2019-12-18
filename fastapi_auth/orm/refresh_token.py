import sqlalchemy as sa

from fastapi_auth.fastapi_util.orm.base import Base
from fastapi_auth.fastapi_util.orm.columns import fk_column
from fastapi_auth.models.user import UserID

# TODO: Make this more override-friendly
#   Could be done via environment variable, or via a mixin approach similar to UserMixin
USER_ID_COLUMN = "user.user_id"


class RefreshToken(Base):
    token = sa.Column("token", sa.String, primary_key=True, index=True)
    user_id: "sa.Column[UserID]" = fk_column(USER_ID_COLUMN)
    exp = sa.Column("exp", sa.Integer, index=True, nullable=False)
