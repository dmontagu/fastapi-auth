from typing import Any, Dict, Optional, Type, TypeVar, Union, overload

from fastapi import FastAPI
from pydantic import ValidationError, parse_obj_as
from requests import Response, Session
from starlette.datastructures import URLPath
from starlette.status import HTTP_200_OK

from fastapi_auth.auth_app import AuthEndpointName
from fastapi_auth.models.auth import AuthTokens
from tests.util.test_base import TestBase


def get_access_headers(
    app: FastAPI, client: Session, username: str, password: str, scope: Optional[str] = None
) -> Dict[str, str]:
    endpoint = app.url_path_for(AuthEndpointName.login)
    login_data = {"username": username, "password": password}
    if scope is not None:
        login_data.update({"scope": scope})
    response = client.post(endpoint, data=login_data)
    if response.status_code != 200:
        raise RuntimeError(response.json())
    tokens = AuthTokens.parse_obj(response.json())
    return {"authorization": f"bearer {tokens.access_token}"}


T = TypeVar("T")


@overload
def structured_request(
    client: Session,
    method: str,
    endpoint: Union[URLPath, str],
    parse_as: Type[T],
    expected_status_code: Optional[int] = HTTP_200_OK,
    **request_kwargs: Any,
) -> T:
    ...


@overload  # noqa F811
def structured_request(
    client: Session,
    method: str,
    endpoint: Union[URLPath, str],
    parse_as: None = None,
    expected_status_code: Optional[int] = HTTP_200_OK,
    **request_kwargs: Any,
) -> Response:
    ...


def structured_request(  # noqa F811
    client: Session,
    method: str,
    endpoint: Union[URLPath, str],
    parse_as: Optional[Type[T]] = None,
    expected_status_code: Optional[int] = HTTP_200_OK,
    **request_kwargs: Any,
) -> Union[T, Response]:
    response = client.request(method, endpoint, **request_kwargs)
    if expected_status_code is not None:
        assert response.status_code == expected_status_code, response.json()
    if parse_as is None:
        return response
    try:
        return parse_obj_as(parse_as, response.json())
    except ValidationError as exc:
        print(response.json())
        raise exc


class TestApiBase(TestBase):
    @property
    def auth_client(self) -> Session:
        raise NotImplementedError

    @overload
    def request(
        self,
        method: str,
        endpoint: Union[URLPath, str],
        parse_as: Type[T],
        expected_status_code: Optional[int] = HTTP_200_OK,
        **request_kwargs: Any,
    ) -> T:
        ...

    @overload  # noqa F811
    def request(
        self,
        method: str,
        endpoint: Union[URLPath, str],
        parse_as: None = None,
        expected_status_code: Optional[int] = HTTP_200_OK,
        **request_kwargs: Any,
    ) -> Response:
        ...

    def request(  # noqa F811
        self,
        method: str,
        endpoint: Union[URLPath, str],
        parse_as: Optional[Type[T]] = None,
        expected_status_code: Optional[int] = HTTP_200_OK,
        **request_kwargs: Any,
    ) -> Union[T, Response]:
        return structured_request(self.auth_client, method, endpoint, parse_as, expected_status_code, **request_kwargs)
