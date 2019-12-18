import logging
from calendar import timegm
from datetime import datetime
from enum import auto
from typing import TYPE_CHECKING, Any, Dict, Generic, List, Optional, Sequence, Tuple, Type, TypeVar

import sqlalchemy as sa
from fastapi import APIRouter, Depends, FastAPI, HTTPException, params
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND

from fastapi_auth.auth_settings import AuthSettings
from fastapi_auth.dependencies import get_headers_token_openapi, get_jwt_user, require_superuser
from fastapi_auth.fastapi_util.api_model import APIMessage
from fastapi_auth.fastapi_util.orm.base import add_base
from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.fastapi_util.util.enums import StrEnum
from fastapi_auth.fastapi_util.util.session import context_session, get_db
from fastapi_auth.fastapi_util.util.tasks import repeat_every
from fastapi_auth.models.auth import AuthRegistrationRequest, AuthTokens, JWTUser, RawPassword, Token, TokenPair
from fastapi_auth.models.user import UserBaseInDB, UserCreate, UserCreateRequest, UserID, UserInDB, UserUpdate
from fastapi_auth.orm.refresh_token import RefreshToken
from fastapi_auth.orm.user import BaseUser
from fastapi_auth.security.json_web_token import generate_tokens
from fastapi_auth.security.password import HashedPassword
from fastapi_auth.util.errors import expected_integrity_error, raise_auth_error, raise_permissions_error

UserCreateT = TypeVar("UserCreateT", bound=UserCreate)
UserCreateRequestT = TypeVar("UserCreateRequestT", bound=UserCreateRequest)
UserInDBT = TypeVar("UserInDBT", bound=UserInDB)
UserUpdateT = TypeVar("UserUpdateT", bound=UserUpdate)

UserApiT = TypeVar("UserApiT", bound=UserBaseInDB)

UserOrmT = TypeVar("UserOrmT", bound=BaseUser)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EndpointNames(StrEnum):
    @classmethod
    def validate_router(cls, router: APIRouter) -> None:
        route_names = {route.name for route in router.routes if isinstance(route, Route)}
        for endpoint_name in cls:
            assert endpoint_name in route_names, f"Missing route: {endpoint_name.name}"


class AuthEndpointName(EndpointNames):
    login = auto()
    refresh = auto()
    validate_token = auto()
    logout = auto()
    logout_all = auto()
    register = auto()
    read_self = auto()
    update_self = auto()


class AdminAuthEndpointName(EndpointNames):
    read_user = auto()
    read_users = auto()
    create_user = auto()
    update_user = auto()


class BaseAuthRouterBuilder(Generic[UserCreateT, UserCreateRequestT, UserInDBT, UserUpdateT, UserApiT, UserOrmT]):
    create_type: Type[UserCreateT]
    create_request_type: Type[UserCreateRequestT]
    in_db_type: Type[UserInDBT]
    update_type: Type[UserUpdateT]
    api_type: Type[UserApiT]
    orm_type: Type[UserOrmT]

    def __init__(self, settings: AuthSettings):
        self.settings = settings

    def __init_subclass__(cls) -> None:
        # TODO: Validate relationships as appropriate, at least the columns and in_db type
        pass

    # ########################
    # ##### Dependencies #####
    # ########################
    @classmethod
    def get_user(cls, db: Session = Depends(get_db), jwt_user: JWTUser = Depends(get_jwt_user)) -> UserInDBT:
        """
        Loads a more complete user model based on a database lookup
        """
        return cls.load_jwt_user(db, jwt_user)

    # ###################################
    # ##### Crud and helper methods #####
    # ###################################
    @classmethod
    def load_jwt_user(cls, db: Session, jwt_user: JWTUser) -> UserInDBT:
        user = cls.read(db=db, user_id=jwt_user.user_id)
        if user is None:
            raise_auth_error(detail="User not found")
        return user

    @classmethod
    def read(cls, db: Session, user_id: UserID) -> Optional[UserInDBT]:
        db_user = db.query(cls.orm_type).filter(cls.orm_type.user_id == user_id).first()
        user = cls.in_db_type(**db_user.dict()) if db_user is not None else None
        return user

    def authenticate(self, db: Session, username: str, password: RawPassword) -> UserInDBT:
        user: Optional[UserOrmT] = db.query(self.orm_type).filter(self.orm_type.username == username).first()
        if user is None:
            raise_auth_error(detail="User not found")
        password_checker = self.settings.password_checker
        result = password_checker.check_sync(password, HashedPassword(user.hashed_password))
        if not result.success:
            raise_auth_error(detail="Incorrect password")
        # TODO: handle result.requires_update (using background task, presumably?)
        return self.in_db_type(**user.dict())

    def create_user(self, db: Session, user_create_request: UserCreateRequestT, is_superuser: bool) -> UserInDBT:
        password_checker = self.settings.password_checker
        hashed_password = password_checker.make_sync(user_create_request.password)
        user_create = self.create_type(
            hashed_password=hashed_password, is_superuser=is_superuser, **user_create_request.dict()
        )
        user = self.orm_type(**user_create.dict())
        user = add_base(db, user)
        return self.in_db_type(**user.dict())

    def update_user(self, db: Session, user_id: UserID, update_request: UserUpdateT) -> UserInDBT:
        user_update = self.update_type(**update_request.dict(exclude_unset=True))
        update_dict: Dict[str, Any] = user_update.dict(exclude_unset=True)
        if update_request.password:
            password_checker = self.settings.password_checker
            hashed_password = password_checker.make_sync(update_request.password)
            update_dict["hashed_password"] = hashed_password

        if not update_dict:
            raise HTTPException(HTTP_400_BAD_REQUEST, "Nothing to update")

        db_user: Optional[UserOrmT] = db.query(self.orm_type).filter(self.orm_type.user_id == user_id).first()
        if not db_user:
            raise HTTPException(HTTP_404_NOT_FOUND, "User not found")

        for attribute, value in update_dict.items():
            setattr(db_user, attribute, value)

        with expected_integrity_error(db, detail="There was a conflict with an existing user"):
            add_base(db, db_user)
        return self.in_db_type.from_orm(db_user)

    # ##################
    # ##### Routes #####
    # ##################
    def get_router(self) -> APIRouter:
        auth_router = APIRouter()
        api_type = self.api_type
        token_url = self.settings.token_url
        refresh_url = self.settings.refresh_url

        if not TYPE_CHECKING:  # pragma: no cover
            UserInDBT = self.in_db_type
            UserUpdateT = self.update_type

        @auth_router.post(
            token_url, response_model=AuthTokens, response_model_exclude_unset=True, response_class=UncachedJSONResponse
        )
        def login(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()) -> AuthTokens:
            """
            OAuth2 compatible token login, get an access token for future requests
            """
            user: UserInDBT = self.authenticate(
                db=db, username=form_data.username, password=RawPassword(form_data.password)
            )
            tokens = self.login_flow(db=db, user=user, scopes=form_data.scopes)
            response = tokens.to_response()
            return response

        @auth_router.post(
            refresh_url,
            response_model=AuthTokens,
            response_model_exclude_unset=True,
            response_class=UncachedJSONResponse,
        )
        def refresh(db: Session = Depends(get_db), token: Token = Depends(get_headers_token_openapi)) -> AuthTokens:
            """
            Consume a refresh token to request a new access token
            """
            tokens = self.refresh_token_flow(db=db, token=token)
            response = tokens.to_response()
            return response

        @auth_router.get(token_url + "/validate", response_model=APIMessage, dependencies=[Depends(self.get_user)])
        def validate_token() -> APIMessage:
            return APIMessage(detail="Token is valid for user")

        @auth_router.get(token_url + "/logout", response_model=APIMessage, response_class=UncachedJSONResponse)
        def logout(db: Session = Depends(get_db), token: Token = Depends(get_headers_token_openapi)) -> APIMessage:
            """
            Invalidate the provided refresh token
            """
            logout_flow(db=db, token=token)
            return APIMessage(detail="Logged out successfully")

        @auth_router.get(token_url + "/logout/all", response_model=APIMessage, response_class=UncachedJSONResponse)
        def logout_all(db: Session = Depends(get_db), token: Token = Depends(get_headers_token_openapi)) -> APIMessage:
            """
            Invalidate all outstanding refresh tokens for the user
            """
            logout_all_flow(db=db, token=token)
            return APIMessage(detail="Logged out all devices successfully")

        @auth_router.post("/register", response_model=api_type)
        def register(*, db: Session = Depends(get_db), request: AuthRegistrationRequest) -> UserInDBT:
            """
            Create new user without the need to be logged in.
            """
            if not self.settings.users_open_registration:
                raise_permissions_error(detail="User registration is not yet open")
            user_create = self.create_request_type(username=request.username, password=request.password)
            with expected_integrity_error(db, detail="This username is already in use"):
                user: UserInDBT = self.create_user(db=db, user_create_request=user_create, is_superuser=False)
            return user

        @auth_router.get("/self", response_model=api_type)
        def read_self(user: UserInDBT = Depends(self.get_user)) -> UserInDBT:
            return user

        @auth_router.patch("/self", response_model=api_type)
        def update_self(
            *, db: Session = Depends(get_db), jwt_user: JWTUser = Depends(get_jwt_user), update_request: UserUpdateT
        ) -> UserInDBT:
            """
            Update a user.
            """
            user: UserInDBT = self.update_user(db=db, user_id=jwt_user.user_id, update_request=update_request)
            return user

        AuthEndpointName.validate_router(auth_router)

        router = APIRouter()
        router.include_router(auth_router, prefix="", tags=["auth"])
        return router

    @staticmethod
    def admin_dependencies() -> Sequence[params.Depends]:
        return require_superuser()

    def get_admin_router(self) -> Tuple[APIRouter, Sequence[params.Depends]]:
        admin_router = APIRouter()
        api_type = self.api_type

        if not TYPE_CHECKING:  # pragma: no cover
            UserCreateRequestT = self.create_request_type
            UserInDBT = self.in_db_type
            UserUpdateT = self.update_type

        @admin_router.get("/users/{user_id}", response_model=api_type)
        def read_user(*, db: Session = Depends(get_db), user_id: UserID) -> UserInDBT:
            """
            Get a specific user by id.
            """
            user = self.read(db=db, user_id=user_id)
            if user is None:
                raise HTTPException(HTTP_404_NOT_FOUND, "User not found")
            return user

        @admin_router.get("/users", response_model=List[api_type])  # type: ignore
        def read_users(db: Session = Depends(get_db), skip: int = 0, limit: int = 100) -> List[UserOrmT]:
            """
            Retrieve users.
            """
            result = db.query(self.orm_type).offset(skip).limit(limit).all()
            return result

        @admin_router.post("/users", response_model=api_type)
        def create_user(
            *, db: Session = Depends(get_db), user_create_request: UserCreateRequestT, is_superuser: bool = False
        ) -> UserInDBT:
            """
            Create new user.
            """
            with expected_integrity_error(db, detail="This username is already in use"):
                user: UserInDBT = self.create_user(
                    db=db, user_create_request=user_create_request, is_superuser=is_superuser
                )
            return user

        @admin_router.patch("/users/{user_id}", response_model=api_type)
        def update_user(*, db: Session = Depends(get_db), user_id: UserID, update_request: UserUpdateT) -> UserInDBT:
            """
            Update a user.
            """
            user: UserInDBT = self.update_user(db=db, user_id=user_id, update_request=update_request)
            return user

        AdminAuthEndpointName.validate_router(admin_router)
        return admin_router, self.admin_dependencies()

    @staticmethod
    def login_flow(db: Session, user: UserInDBT, scopes: List[str]) -> "TokenPair":
        token_pair = _create_tokens(db=db, user=user, scopes=scopes)
        return token_pair

    def refresh_token_flow(self, db: Session, token: "Token") -> "TokenPair":
        """
        Implements the refresh token flow by performing the following steps:
        * Delete the provided refresh token
        * Generate and return a new refresh (and access) token
        """
        user: Optional[UserInDBT] = self.read(db=db, user_id=token.payload.sub)
        if user is None:
            raise_auth_error(detail="User not found; try logging in again")
        _consume_refresh_token(db=db, token=token)
        token_pair = _create_tokens(db=db, user=user, scopes=token.payload.scopes)
        return token_pair

    def setup_first_superuser(self, engine: sa.engine.Engine, **extra_create_kwargs: Any) -> None:
        settings = self.settings
        username = settings.first_superuser
        password = RawPassword(settings.first_superuser_password) if settings.first_superuser_password else None
        assert username, f"Invalid superuser username: {username}"
        assert password, f"Invalid superuser password: {password}"
        user_create = self.create_request_type(username=username, password=password, **extra_create_kwargs)

        with context_session(engine) as session:
            try:
                self.create_user(db=session, user_create_request=user_create, is_superuser=True)
                logger.info("First superuser created.")
            except IntegrityError:
                session.rollback()
                logger.info("First superuser already exists.")

    def add_expired_token_cleanup(self, app: FastAPI) -> None:
        add_expired_token_cleanup(app, self.settings.refresh_token_cleanup_interval_seconds)

    def include_auth(
        self,
        router: APIRouter,
        include_admin_routes: bool = True,
        auth_prefix: str = "/auth",
        admin_prefix: str = "/admin",
    ) -> None:
        auth_router = self.get_router()
        router.include_router(auth_router, prefix=auth_prefix, default_response_class=JSONResponse)
        if include_admin_routes:
            admin_auth_router, admin_deps = self.get_admin_router()
            router.include_router(
                admin_auth_router,
                prefix=admin_prefix,
                tags=["admin-auth"],
                dependencies=admin_deps,
                default_response_class=JSONResponse,
            )


def remove_expired_tokens(db: Session) -> int:
    """
    Returns the number of removed expired tokens (e.g., for logging)
    """
    now = get_epoch()
    filtered = db.query(RefreshToken).filter(RefreshToken.exp < now)
    n_expired_tokens = filtered.count()
    filtered.delete()
    db.commit()
    return n_expired_tokens


def get_epoch() -> int:
    """
    Returns the number of seconds since the epoch
    """
    return timegm(datetime.utcnow().utctimetuple())


def logout_flow(db: Session, token: "Token") -> None:
    """
    Deletes the provided refresh token
    """
    _consume_refresh_token(db=db, token=token)


def logout_all_flow(db: Session, token: "Token") -> None:
    """
    Deletes all refresh tokens for the token's specified user
    """
    _consume_refresh_token(db=db, token=token)
    db.query(RefreshToken).filter(RefreshToken.user_id == token.payload.sub).delete(synchronize_session=False)
    db.commit()


def _create_tokens(db: Session, user: UserInDB, scopes: List[str]) -> "TokenPair":
    token_pair = generate_tokens(user_id=user.user_id, is_superuser=user.is_superuser, scopes=scopes)
    refresh_token = RefreshToken(
        token=token_pair.refresh.encoded, user_id=token_pair.refresh.payload.sub, exp=token_pair.refresh.payload.exp
    )
    add_base(db, refresh_token)
    return token_pair


def _consume_refresh_token(db: Session, token: "Token") -> None:
    """
    First validates that it hasn't already been used, then deletes it
    """
    # Validate that the token is in the database, even though it passed decoding
    # This is critical to ensure previously used / logged out tokens don't work
    refresh_token = db.query(RefreshToken).filter(RefreshToken.token == token.encoded).first()
    if refresh_token is None:
        raise_auth_error(detail="Provided token was not a valid refresh token")
    db.delete(refresh_token)
    db.commit()


AnyRouterBuilder = BaseAuthRouterBuilder[Any, Any, Any, Any, Any, Any]


def get_auth_app(
    router_builder: AnyRouterBuilder,
    include_admin_routes: bool,
    openapi_url: Optional[str] = None,
    docs_url: Optional[str] = None,
    redoc_url: Optional[str] = None,
    swagger_ui_oauth2_redirect_url: Optional[str] = None,
    **fastapi_kwargs: Any,
) -> FastAPI:
    fastapi_kwargs.setdefault("debug", get_api_settings().debug)
    auth_app = FastAPI(
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
        swagger_ui_oauth2_redirect_url=swagger_ui_oauth2_redirect_url,
        **fastapi_kwargs,
    )
    router_builder.include_auth(auth_app.router, include_admin_routes=include_admin_routes, auth_prefix="")
    router_builder.add_expired_token_cleanup(auth_app)
    return auth_app


def add_expired_token_cleanup(app: FastAPI, delay: int) -> None:
    @app.on_event("startup")
    @repeat_every(seconds=delay)
    def remove_expired_tokens_task() -> None:  # pragma: no cover
        with context_session() as db:
            remove_expired_tokens(db=db)


class UncachedJSONResponse(JSONResponse):
    def __init__(
        self,
        content: Any = None,
        status_code: int = 200,
        headers: Dict[str, str] = None,
        media_type: str = None,
        background: BackgroundTask = None,
    ) -> None:
        headers = headers or {}
        headers.update({"Cache-Control": "no-store", "Pragma": "no-cache"})
        super().__init__(content, status_code, headers, media_type, background)
