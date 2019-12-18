import uuid
from typing import no_type_check

from sqlalchemy.dialects.postgresql.base import UUID
from sqlalchemy.sql.sqltypes import CHAR
from sqlalchemy.sql.type_api import TypeDecorator


class GUID(TypeDecorator):  # type: ignore
    """
    Platform-independent GUID type.

    Uses PostgreSQL's UUID type, otherwise uses CHAR(32), storing as stringified hex values.

    Taken from SQLAlchemy docs: https://docs.sqlalchemy.org/en/13/core/custom_types.html#backend-agnostic-guid-type
    """

    impl = CHAR

    @no_type_check
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @no_type_check
    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(UUID())
        else:
            return dialect.type_descriptor(CHAR(32))

    @no_type_check
    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == "postgresql":
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    @no_type_check
    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value
