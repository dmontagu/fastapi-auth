from contextlib import contextmanager
from typing import Dict, Generator, NoReturn, Optional, Type

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_409_CONFLICT

from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings

DEFAULT_ERROR_MESSAGE = "An error occurred"
DEFAULT_AUTH_ERROR_MSG = "Authentication failed"
DEFAULT_PERMS_ERROR_MSG = "Insufficient permissions"
AUTH_ERROR_HEADERS = {"WWW-Authenticate": "Bearer"}


def raise_auth_error(status_code: int = HTTP_401_UNAUTHORIZED, detail: str = DEFAULT_AUTH_ERROR_MSG) -> NoReturn:
    _raise_api_response_error(detail, status_code, headers=AUTH_ERROR_HEADERS)


def raise_permissions_error(status_code: int = HTTP_403_FORBIDDEN, detail: str = DEFAULT_PERMS_ERROR_MSG) -> NoReturn:
    raise_auth_error(status_code=status_code, detail=detail)


def raise_integrity_error(
    session: Session, status_code: int = HTTP_409_CONFLICT, detail: Optional[str] = None
) -> NoReturn:
    session.rollback()
    _raise_api_response_error(detail=detail, status_code=status_code)


@contextmanager
def expected_exceptions(
    *except_types: Type[Exception],
    status_code: int = HTTP_400_BAD_REQUEST,
    detail: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Generator[None, None, None]:
    try:
        yield
    except except_types as exc:
        _raise_api_response_error(detail, status_code, headers, exc=exc)


@contextmanager
def expected_auth_error(
    *except_types: Type[Exception],
    status_code: int = HTTP_401_UNAUTHORIZED,
    detail: Optional[str] = DEFAULT_AUTH_ERROR_MSG,
) -> Generator[None, None, None]:
    try:
        yield
    except except_types as exc:
        _raise_api_response_error(detail, status_code, headers=AUTH_ERROR_HEADERS, exc=exc)


@contextmanager
def expected_integrity_error(
    session: Session, status_code: int = HTTP_409_CONFLICT, detail: Optional[str] = None
) -> Generator[None, None, None]:
    try:
        yield
    except IntegrityError as exc:
        session.rollback()
        _raise_api_response_error(detail, status_code, exc=exc)


def _raise_api_response_error(
    detail: Optional[str], status_code: int, headers: Optional[Dict[str, str]] = None, exc: Optional[Exception] = None
) -> NoReturn:
    if get_api_settings().debug and exc is not None:
        detail = str(exc)
    if detail is None:
        detail = DEFAULT_ERROR_MESSAGE
    raise HTTPException(status_code=status_code, detail=detail, headers=headers)
