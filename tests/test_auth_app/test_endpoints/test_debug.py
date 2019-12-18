from calendar import timegm
from datetime import datetime
from typing import Dict, List, Optional, TypeVar
from uuid import uuid4

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from starlette.status import (
    HTTP_200_OK,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
)

import fastapi_auth.auth_app
from fastapi_auth.auth_app import AdminAuthEndpointName, AuthEndpointName, get_epoch, remove_expired_tokens
from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.api_model import APIMessage
from fastapi_auth.fastapi_util.util.session import context_session
from fastapi_auth.models.auth import AuthTokens
from fastapi_auth.models.user import UserID
from fastapi_auth.orm.refresh_token import RefreshToken
from fastapi_auth.security.json_web_token import generate_tokens
from fastapi_auth.util.cache import clear_caches
from tests.test_auth_app.test_endpoints.shared import (
    TestAuthApiBase,
    admin_username2,
    email3,
    password1,
    password2,
    password3,
    username1,
    username2,
    username3,
)
from tests.util.custom_user import User, UserCreateRequest, UserResult, UserUpdate

AuthUser = UserResult
AuthUpdateRequest = UserUpdate

T = TypeVar("T")


class TestDebug(TestAuthApiBase):
    fixture_names = ("debug_auth_app",)
    debug_auth_app: FastAPI

    @property
    def auth_app(self) -> FastAPI:
        return self.debug_auth_app

    @pytest.fixture(scope="module")
    def registered_user(self, monkeypatch_module: MonkeyPatch, debug_auth_app: FastAPI) -> AuthUser:
        self.debug_auth_app = debug_auth_app
        return self._get_registration_response(AuthUser)

    @pytest.fixture(scope="module")
    def admin_tokens(self, debug_auth_app: FastAPI) -> AuthTokens:
        self.debug_auth_app = debug_auth_app
        tokens = self._get_admin_tokens(admin_scope=True)
        assert tokens.expires_in is None
        return tokens

    @pytest.fixture(scope="module")
    def non_admin_tokens(self, debug_auth_app: FastAPI) -> AuthTokens:
        self.debug_auth_app = debug_auth_app
        return self._get_admin_tokens(admin_scope=False)

    @pytest.fixture(scope="module")
    def admin_access_headers(self, admin_tokens: AuthTokens, debug_auth_app: FastAPI) -> Dict[str, str]:
        self.debug_auth_app = debug_auth_app
        return {"authorization": f"bearer {admin_tokens.access_token}"}

    @pytest.fixture(scope="module")
    def non_admin_access_headers(self, non_admin_tokens: AuthTokens, debug_auth_app: FastAPI) -> Dict[str, str]:
        self.debug_auth_app = debug_auth_app
        return {"authorization": f"bearer {non_admin_tokens.access_token}"}

    @pytest.fixture(scope="module")
    def refresh_headers(self, non_admin_tokens: AuthTokens, debug_auth_app: FastAPI) -> Dict[str, str]:
        self.debug_auth_app = debug_auth_app
        return {"authorization": f"bearer {non_admin_tokens.refresh_token}"}

    def test_login(self, admin_tokens: AuthTokens) -> None:
        assert admin_tokens.token_type == "bearer"  # the fixture is the test

    def test_login_password_fails(self) -> None:
        admin_username = get_auth_settings().first_superuser
        assert admin_username is not None
        bad_password = "wrong"
        message = self._get_login_response(admin_username, bad_password, APIMessage, HTTP_401_UNAUTHORIZED)
        assert message.detail == "Incorrect password"

    def test_login_username_fails(self) -> None:
        bad_username = "bad@test.com"
        bad_password = "wrong"
        message = self._get_login_response(bad_username, bad_password, APIMessage, HTTP_401_UNAUTHORIZED)
        assert message.detail == "User not found"

    def test_read_users(self, admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.read_users)
        self.request("GET", url, List[AuthUser], headers=admin_access_headers)

    def test_register(self, registered_user: AuthUser) -> None:
        assert registered_user.username == username1

        # Confirm login works for the new user
        login_url = self.debug_auth_app.url_path_for(AuthEndpointName.login)
        body_data = {"username": username1, "password": password1}
        self.request("POST", login_url, AuthTokens, HTTP_200_OK, data=body_data)

    def test_create_user(
        self, admin_access_headers: Dict[str, str], non_admin_access_headers: Dict[str, str], registered_user: AuthUser
    ) -> None:
        user_create_request_1 = UserCreateRequest(username=username1, password=password1)
        create_user_url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.create_user)

        body_json = jsonable_encoder(user_create_request_1)
        message = self.request("POST", create_user_url, APIMessage, HTTP_401_UNAUTHORIZED, json=body_json)
        assert message.detail == "Not authenticated"

        message = self.request(
            "POST", create_user_url, APIMessage, HTTP_403_FORBIDDEN, json=body_json, headers=non_admin_access_headers
        )
        assert message.detail == "Insufficient permissions"

        user_create_request_2 = UserCreateRequest(username=username3, password=password3, email=email3)
        body_json = jsonable_encoder(user_create_request_2)
        created_user_model = self.request(
            "POST", create_user_url, AuthUser, json=body_json, headers=admin_access_headers
        )
        assert created_user_model.username == username3
        assert created_user_model.email == email3
        with context_session() as session:
            created_user: User = session.query(User).get(created_user_model.user_id)
            assert created_user is not None
            assert not created_user.is_superuser
            assert created_user.email == email3

    def test_read_user(self, admin_access_headers: Dict[str, str], registered_user: AuthUser) -> None:
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.read_user, user_id=str(registered_user.user_id))
        auth_user = self.request("GET", url, AuthUser, HTTP_200_OK, headers=admin_access_headers)
        assert auth_user.username == registered_user.username
        assert auth_user.username == registered_user.username

    def test_read_user_fails(self, admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.read_user, user_id=str(uuid4()))
        message = self.request("GET", url, APIMessage, HTTP_404_NOT_FOUND, headers=admin_access_headers)
        assert message.detail == "User not found"

    def test_reregister_fails(self, monkeypatch: MonkeyPatch, registered_user: AuthUser) -> None:
        monkeypatch.setenv("API_DEBUG", "0")
        clear_caches()
        message = self._get_registration_response(APIMessage, HTTP_409_CONFLICT)
        assert message.detail == "This username is already in use"

    def test_refresh(self, admin_access_headers: Dict[str, str], refresh_headers: Dict[str, str]) -> None:
        refresh_url = self.debug_auth_app.url_path_for(AuthEndpointName.refresh)
        self.request("POST", refresh_url, AuthTokens, HTTP_200_OK, headers=refresh_headers)

        message = self.request("POST", refresh_url, APIMessage, HTTP_401_UNAUTHORIZED, headers=refresh_headers)
        assert message.detail == "Provided token was not a valid refresh token"

        message = self.request("POST", refresh_url, APIMessage, HTTP_401_UNAUTHORIZED, headers=admin_access_headers)
        assert message.detail == "Provided token was not a valid refresh token"

    @pytest.mark.parametrize(
        "headers", [None, {"authorization": f"bearer"}, {"authorization": f"bearer "}, {"authorization": f"bearer bad"}]
    )
    def test_token_problems(self, headers: Optional[Dict[str, str]], admin_tokens: AuthTokens) -> None:
        if headers is None:
            # Workaround for accessing fixtures in parametrized inputs
            headers = {"authorization": f"nonbearer {admin_tokens.refresh_token}"}
        url = self.debug_auth_app.url_path_for(AuthEndpointName.refresh)
        message = self.request("POST", url, APIMessage, HTTP_401_UNAUTHORIZED, headers=headers)
        assert message.detail == "Invalid token", headers

    def test_refresh_fails(self) -> None:
        url = self.debug_auth_app.url_path_for(AuthEndpointName.refresh)

        fake_auth_user = AuthUser(user_id=UserID(uuid4()), username="hello@test.com")
        invalid_user_tokens = generate_tokens(user_id=fake_auth_user.user_id, is_superuser=False, scopes=[])
        headers = {"authorization": f"bearer {invalid_user_tokens.refresh.encoded}"}

        message = self.request("POST", url, APIMessage, HTTP_401_UNAUTHORIZED, headers=headers)
        assert message.detail == "User not found; try logging in again"

    def test_validate(
        self,
        admin_access_headers: Dict[str, str],
        non_admin_access_headers: Dict[str, str],
        refresh_headers: Dict[str, str],
    ) -> None:
        url = self.debug_auth_app.url_path_for(AuthEndpointName.validate_token)
        for headers in [admin_access_headers, non_admin_access_headers, refresh_headers]:
            message = self.request("GET", url, APIMessage, HTTP_200_OK, headers=headers)
            assert message.detail == "Token is valid for user"

    def test_validate_fails(self) -> None:
        fake_auth_user = AuthUser(user_id=UserID(uuid4()), username="hello@test.com")
        invalid_user_tokens = generate_tokens(user_id=fake_auth_user.user_id, is_superuser=False, scopes=[])
        headers = {"authorization": f"bearer {invalid_user_tokens.access.encoded}"}
        url = self.debug_auth_app.url_path_for(AuthEndpointName.validate_token)
        message = self.request("GET", url, APIMessage, HTTP_401_UNAUTHORIZED, headers=headers)
        assert message.detail == "User not found"

    def test_update_username(self, registered_user: AuthUser, admin_access_headers: Dict[str, str]) -> None:
        payload = jsonable_encoder(AuthUpdateRequest(username=username2).dict(exclude_unset=True))
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.update_user, user_id=str(registered_user.user_id))
        updated_user = self.request("PATCH", url, AuthUser, headers=admin_access_headers, json=payload)
        assert updated_user.user_id == registered_user.user_id
        assert registered_user.username != username2
        assert updated_user.username == username2

        # Ensure registered_user still has a valid username
        registered_user.username = username2
        self._get_login_response(registered_user.username, password1, AuthTokens)

    def test_update_password(self, registered_user: AuthUser, admin_access_headers: Dict[str, str]) -> None:
        payload = jsonable_encoder(AuthUpdateRequest(password=password2).dict(exclude_unset=True))
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.update_user, user_id=str(registered_user.user_id))
        updated_user = self.request("PATCH", url, AuthUser, headers=admin_access_headers, json=payload)
        assert updated_user.user_id == registered_user.user_id
        assert registered_user.username == updated_user.username

        # Ensure new password succeeds for login
        self._get_login_response(registered_user.username, password2, AuthTokens)

    def test_empty_update_fails(self, registered_user: AuthUser, admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.update_user, user_id=str(registered_user.user_id))
        payload = jsonable_encoder(AuthUpdateRequest().dict(exclude_unset=True))
        message = self.request(
            "PATCH", url, APIMessage, HTTP_400_BAD_REQUEST, headers=admin_access_headers, json=payload
        )
        assert message.detail == "Nothing to update"

    def test_missing_user_update_fails(self, registered_user: AuthUser, admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AdminAuthEndpointName.update_user, user_id=str(uuid4()))
        payload = jsonable_encoder(AuthUpdateRequest(username="hello@test.com").dict(exclude_unset=True))
        message = self.request("PATCH", url, APIMessage, HTTP_404_NOT_FOUND, headers=admin_access_headers, json=payload)
        assert message.detail == "User not found"

    def test_admin_fails(self, registered_user: AuthUser) -> None:
        message = self._get_login_response(
            registered_user.username, password2, APIMessage, HTTP_403_FORBIDDEN, admin_scope=True
        )
        assert message.detail == "Insufficient permissions"

    def test_logout(self) -> None:
        tokens = self._get_admin_tokens()
        url = self.debug_auth_app.url_path_for(AuthEndpointName.logout)
        refresh_headers = {"authorization": f"bearer {tokens.refresh_token}"}
        message = self.request("GET", url, APIMessage, headers=refresh_headers)
        assert message.detail == "Logged out successfully"

        message = self.request("GET", url, APIMessage, HTTP_401_UNAUTHORIZED, headers=refresh_headers)
        assert message.detail == "Provided token was not a valid refresh token"

    def test_logout_all(self) -> None:
        tokens = self._get_admin_tokens()
        tokens2 = self._get_admin_tokens()
        refresh_headers = {"authorization": f"bearer {tokens.refresh_token}"}
        refresh_headers2 = {"authorization": f"bearer {tokens2.refresh_token}"}

        url = self.debug_auth_app.url_path_for(AuthEndpointName.logout_all)
        message = self.request("GET", url, APIMessage, headers=refresh_headers)
        assert message.detail == "Logged out all devices successfully"

        message = self.request("GET", url, APIMessage, HTTP_401_UNAUTHORIZED, headers=refresh_headers2)
        assert message.detail == "Provided token was not a valid refresh token"

    def test_scopes(self, registered_user: AuthUser) -> None:
        with pytest.raises(HTTPException) as exc_info:
            generate_tokens(user_id=registered_user.user_id, is_superuser=False, scopes=["unexpected"])
        assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Unrecognized scope: 'unexpected'"

    def test_remove_expired_tokens(self, monkeypatch: MonkeyPatch) -> None:
        auth_settings = get_auth_settings()

        def real_get_epoch() -> int:
            return timegm(datetime.utcnow().utctimetuple())  # seconds since epoch

        assert abs(get_epoch() - real_get_epoch()) <= 1

        def refresh_not_expired_epoch() -> int:
            return real_get_epoch() + auth_settings.refresh_token_expire_seconds - 100

        def refresh_expired_epoch() -> int:
            return real_get_epoch() + auth_settings.refresh_token_expire_seconds + 100

        with context_session() as session:
            assert len(session.query(RefreshToken).all()) == 3

            assert remove_expired_tokens(db=session) == 0
            assert len(session.query(RefreshToken).all()) == 3

            monkeypatch.setattr(fastapi_auth.auth_app, "get_epoch", refresh_not_expired_epoch)
            assert remove_expired_tokens(db=session) == 0
            assert len(session.query(RefreshToken).all()) == 3

            monkeypatch.setattr(fastapi_auth.auth_app, "get_epoch", refresh_expired_epoch)
            assert remove_expired_tokens(db=session) == 3

            assert len(session.query(RefreshToken).all()) == 0

    def test_read_self(self, non_admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AuthEndpointName.read_self)
        self_user = self.request("GET", url, AuthUser, headers=non_admin_access_headers)
        assert self_user.username == get_auth_settings().first_superuser

    def test_update_self_fails(self, non_admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AuthEndpointName.update_self)
        payload = jsonable_encoder(AuthUpdateRequest(username=username2))
        message = self.request(
            "PATCH", url, APIMessage, HTTP_409_CONFLICT, headers=non_admin_access_headers, json=payload
        )
        assert message.detail == "There was a conflict with an existing user"

    def test_update_self(self, non_admin_access_headers: Dict[str, str]) -> None:
        url = self.debug_auth_app.url_path_for(AuthEndpointName.update_self)
        payload = jsonable_encoder(AuthUpdateRequest(username=admin_username2))
        updated_user = self.request("PATCH", url, AuthUser, headers=non_admin_access_headers, json=payload)
        assert updated_user.username == admin_username2
