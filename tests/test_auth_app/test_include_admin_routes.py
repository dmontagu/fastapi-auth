from tests.test_auth_app.build_app import get_test_app


def test_excluded() -> None:
    app = get_test_app(include_admin_routes=False)
    assert len(app.router.routes) == 9


def test_included() -> None:
    app = get_test_app(include_admin_routes=True)
    assert len(app.router.routes) == 13
