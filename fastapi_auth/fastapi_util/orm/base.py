from typing import TYPE_CHECKING, Any, Dict, TypeVar

import sqlalchemy as sa
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base, declared_attr
from sqlalchemy.orm import Session
from sqlalchemy.sql.base import ImmutableColumnCollection

from fastapi_auth.fastapi_util.util.camelcase import camel2snake

T = TypeVar("T", bound="CustomBase")

MYPY = False


class CustomMeta(DeclarativeMeta):
    __table__: sa.Table

    @property
    def columns(cls) -> ImmutableColumnCollection:
        return cls.__table__.columns


class CustomBase:
    __table__: sa.Table

    if TYPE_CHECKING:
        __tablename__: str
    else:

        @declared_attr
        def __tablename__(cls) -> str:
            return camel2snake(cls.__name__)

    def dict(self) -> Dict[str, Any]:
        return {key: getattr(self, key) for key in self.__table__.c.keys()}


_Base = declarative_base(cls=CustomBase, metaclass=CustomMeta)
if TYPE_CHECKING:
    # This is necessary for pycharm, but not mypy
    class Base(_Base, CustomBase, metaclass=CustomMeta):
        __table__: sa.Table
        __tablename_: str
        metadata: sa.MetaData
        columns: ImmutableColumnCollection
        if not MYPY:  # pragma: no cover
            # Suppress pycharm kwargs warnings
            def __init__(self, **kwargs: Any) -> None:
                pass

        def dict(self) -> Dict[str, Any]:
            ...


else:
    exec("Base = _Base")  # Need to hide from PyCharm
S = TypeVar("S", bound="Base")


def add_base(session: Session, item: S) -> S:
    session.add(item)
    session.commit()
    return item
