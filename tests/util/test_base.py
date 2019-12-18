from typing import Any, Tuple

import pytest


class TestBase:
    fixture_names: Tuple[str, ...] = ()

    @pytest.fixture(autouse=True)
    def auto_injector_fixture(self, request: Any) -> None:
        names = self.fixture_names
        for name in names:
            setattr(self, name, request.getfixturevalue(name))
