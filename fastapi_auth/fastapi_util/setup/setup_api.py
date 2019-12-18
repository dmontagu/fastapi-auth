from fastapi import FastAPI
from fastapi.routing import APIRoute


def setup_openapi(app: FastAPI) -> None:
    """ Simplify operation IDs so that generated clients have simpler api function names """
    for route in app.routes:
        if isinstance(route, APIRoute):
            route.operation_id = route.name
