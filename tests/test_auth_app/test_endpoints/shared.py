from typing import Type, TypeVar

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from requests import Session
from starlette.status import HTTP_200_OK
from starlette.testclient import TestClient

from fastapi_auth.auth_app import AuthEndpointName
from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.models.auth import AuthRegistrationRequest, AuthTokens
from fastapi_auth.security.password import RawPassword
from tests.util.test_api_base import TestApiBase

username1 = email1 = "user@test.com"
username2 = email2 = "user2@test.com"
username3 = email3 = "user3@test.com"
admin_username2 = "admin2@test.com"
password1 = RawPassword("password")
password2 = RawPassword("password2")
password3 = RawPassword("password3")

T = TypeVar("T")


class TestAuthApiBase(TestApiBase):
    @property
    def auth_app(self) -> FastAPI:
        raise NotImplementedError

    @property
    def auth_client(self) -> Session:
        return TestClient(self.auth_app)

    def _get_registration_response(self, result_type: Type[T], expected_status_code: int = HTTP_200_OK) -> T:
        register_url = self.auth_app.url_path_for(AuthEndpointName.register)
        registration_request = AuthRegistrationRequest(username=username1, password=password1)
        body_json = jsonable_encoder(registration_request)
        return self.request(
            "POST", register_url, parse_as=result_type, expected_status_code=expected_status_code, json=body_json
        )

    def _get_login_response(
        self,
        username: str,
        password: str,
        result_type: Type[T],
        expected_status_code: int = HTTP_200_OK,
        admin_scope: bool = False,
    ) -> T:
        login_data = {"username": username, "password": password}
        if admin_scope:
            login_data.update({"scope": "admin"})
        url = self.auth_app.url_path_for(AuthEndpointName.login)
        return self.request("POST", url, result_type, expected_status_code, data=login_data)

    def _get_admin_tokens(self, admin_scope: bool = False) -> AuthTokens:
        auth_settings = get_auth_settings()
        admin_username = auth_settings.first_superuser
        admin_password = auth_settings.first_superuser_password
        assert admin_username is not None
        assert admin_password is not None
        return self._get_login_response(admin_username, admin_password, AuthTokens, admin_scope=admin_scope)
