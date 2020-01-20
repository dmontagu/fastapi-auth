import sqlalchemy as sa
from fastapi_utils.guid_type import GUID

from fastapi_auth.models.user import UserID

# TODO: Make this more override-friendly
#   Could be done via environment variable, or via a mixin approach similar to UserMixin
USER_ID_COLUMN = "user.user_id"


class RefreshToken(Base):
    token = sa.Column("token", sa.String, primary_key=True, index=True)
    user_id: "sa.Column[UserID]" = sa.Column(GUID, sa.ForeignKey(USER_ID_COLUMN), nullable=False)
    exp = sa.Column("exp", sa.Integer, index=True, nullable=False)
