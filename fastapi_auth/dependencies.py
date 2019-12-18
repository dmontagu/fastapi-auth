import logging
from typing import Dict, Sequence

from fastapi import Depends, Header, params
from fastapi.openapi.models import OAuthFlowPassword, OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from fastapi.security.utils import get_authorization_scheme_param

from fastapi_auth.auth_settings import get_auth_settings
from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from fastapi_auth.models.auth import Token
from fastapi_auth.models.user import JWTUser
from fastapi_auth.security.json_web_token import get_validated_token
from fastapi_auth.util.errors import raise_auth_error

logger = logging.getLogger(__name__)


class OAuth2RefreshPasswordBearer(OAuth2PasswordBearer):
    def __init__(
        self,
        token_url: str,
        refresh_url: str,
        scheme_name: str = None,
        scopes: Dict[str, str] = None,
        auto_error: bool = True,
    ):
        if not scopes:  # pragma: no cover
            scopes = {}
        flows = OAuthFlowsModel(password=OAuthFlowPassword(tokenUrl=token_url, refreshUrl=refresh_url, scopes=scopes))
        super(OAuth2PasswordBearer, self).__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)


def get_reusable_oauth2() -> OAuth2RefreshPasswordBearer:
    settings = get_auth_settings()
    url_base = settings.api_prefix
    token_url = url_base + settings.token_url
    refresh_url = url_base + settings.refresh_url
    scopes = settings.expected_scopes
    return OAuth2RefreshPasswordBearer(token_url=token_url, refresh_url=refresh_url, scopes=scopes, auto_error=True)


def get_headers_token(security_scopes: SecurityScopes, encoded: str = Depends(get_reusable_oauth2())) -> Token:
    """
    This FastAPI dependency *will not* result in an argument added to the OpenAPI spec.

    This should generally be used for dependencies involving the access token.
    """
    return get_validated_token(security_scopes.scopes, encoded)


def get_headers_token_openapi(security_scopes: SecurityScopes, authorization: str = Header(None)) -> Token:
    """
    This FastAPI dependency *will* result in an argument added to the OpenAPI spec.

    This should generally be used for dependencies using something besides the access token (e.g., refresh token).
    """
    scheme, param = get_authorization_scheme_param(authorization)
    if not param or scheme.lower() != "bearer":
        raise_auth_error(detail="Invalid token")
    return get_validated_token(security_scopes.scopes, param)


def get_jwt_user(token: Token = Depends(get_headers_token)) -> JWTUser:
    """
    Does not require a database lookup, unlike get_user
    """
    return token.jwt_user()


def require_superuser() -> Sequence[params.Depends]:
    """
    Returns a list of dependencies containing one that will require superuser access, *UNLESS*
    api_settings indicates otherwise (for development purposes).

    (In that case, no dependencies are added but a warning is emitted.)
    """
    if get_api_settings().disable_superuser_dependency:
        logger.warning(f"*** require_superuser is DISABLED ***")
        return []
    return [params.Security(get_jwt_user, scopes=[get_auth_settings().superuser_scope])]
