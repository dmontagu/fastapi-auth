from typing import Dict

import pytest
from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from starlette.status import HTTP_403_FORBIDDEN, HTTP_409_CONFLICT

from fastapi_auth.auth_app import AdminAuthEndpointName
from fastapi_auth.fastapi_util.api_model import APIMessage
from fastapi_auth.models.auth import AuthTokens
from fastapi_auth.models.user import UserCreateRequest
from tests.test_auth_app.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.test_auth_app.test_endpoints.shared import TestAuthApiBase


class TestProd(TestAuthApiBase):
    fixture_names = ("prod_auth_app",)
    prod_auth_app: FastAPI

    @property
    def auth_app(self) -> FastAPI:
        return self.prod_auth_app

    @pytest.fixture(scope="module")
    def admin_tokens(self, prod_auth_app: FastAPI) -> AuthTokens:
        self.prod_auth_app = prod_auth_app
        return self._get_admin_tokens(admin_scope=True)

    @pytest.fixture(scope="module")
    def admin_access_headers(self, admin_tokens: AuthTokens) -> Dict[str, str]:
        return {"authorization": f"bearer {admin_tokens.access_token}"}

    def test_expires_in_missing(self, admin_tokens: AuthTokens) -> None:
        assert admin_tokens.expires_in is not None

    def test_create_user(self, admin_access_headers: Dict[str, str]) -> None:
        create_user_url = self.auth_app.url_path_for(AdminAuthEndpointName.create_user)

        user_create_request_1 = UserCreateRequest(username=ADMIN_USERNAME, password=ADMIN_PASSWORD)
        body_json = jsonable_encoder(user_create_request_1)
        message = self.request(
            "POST", create_user_url, APIMessage, HTTP_409_CONFLICT, json=body_json, headers=admin_access_headers
        )
        assert message.detail == "This username is already in use"

    def test_registration_closed(self) -> None:
        message = self._get_registration_response(APIMessage, HTTP_403_FORBIDDEN)
        assert message.detail == "User registration is not yet open"
