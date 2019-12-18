import json
from pathlib import Path
from typing import Any, Dict

import pytest
from starlette.status import HTTP_404_NOT_FOUND
from starlette.testclient import TestClient

from fastapi_auth.fastapi_util.settings.api_settings import get_api_settings
from tests.test_auth_app.build_app import get_test_app

openapi_url = "/openapi.json"

admin_schema_path = Path(__file__).parent / "schemas" / "admin.json"
non_admin_schema_path = Path(__file__).parent / "schemas" / "non_admin.json"


def load_schema(path: Path) -> Dict[str, Any]:
    with path.open("r") as f:
        contents = f.read()
    return json.loads(contents)


def save_schema(schema: Dict[str, Any], path: Path) -> None:
    contents = json.dumps(schema, sort_keys=True, indent=4)
    with path.open("r") as f:
        existing_contents = f.read()
    if existing_contents != contents:
        with path.open("w") as f:
            f.write(contents)


@pytest.mark.parametrize(
    "include_admin_routes,schema_path", [(True, admin_schema_path), (False, non_admin_schema_path)]
)
def test_openapi_schema_generation(include_admin_routes: bool, schema_path: Path) -> None:
    get_api_settings.cache_clear()
    app = get_test_app(include_admin_routes=include_admin_routes)
    schema = app.openapi()

    save_schema(schema, schema_path)
    assert schema == load_schema(schema_path)


def test_auth_openapi_fails() -> None:
    app = get_test_app(openapi_url=None)
    client = TestClient(app)
    response = client.get(openapi_url)
    assert response.status_code == HTTP_404_NOT_FOUND
