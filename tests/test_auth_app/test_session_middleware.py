from typing import NoReturn

import pytest
from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from fastapi_auth.fastapi_util.util.session import context_session, get_db
from tests.util.custom_user import User


def test_session_rollback(debug_auth_app: FastAPI) -> None:
    debug_client = TestClient(debug_auth_app)
    rollback_endpoint = "/session_rollback"
    non_rollback_endpoint = "/non_session_rollback"

    class Sentinel(Exception):
        pass

    @debug_auth_app.get(rollback_endpoint)
    def session_rollback(db: Session = Depends(get_db)) -> NoReturn:
        user = User(username="fail@test.com", hashed_password="fail")
        db.add(user)
        raise Sentinel

    @debug_auth_app.get(non_rollback_endpoint)
    def session_non_rollback(db: Session = Depends(get_db)) -> None:
        user = User(username="faiaoeul@test.com", hashed_password="fail", is_superuser=False)
        db.add(user)
        db.commit()

    with context_session() as sess:
        original_n_users = len(sess.query(User).all())

        with pytest.raises(Sentinel):
            debug_client.get(rollback_endpoint)
        assert len(sess.query(User).all()) == original_n_users

        debug_client.get(non_rollback_endpoint)
        assert len(sess.query(User).all()) == original_n_users + 1
