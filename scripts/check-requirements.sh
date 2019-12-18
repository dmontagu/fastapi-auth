#!/usr/bin/env bash

check_for_python3() {
  command -v python3 >/dev/null 2>&1 || {
    cat <<ERROR >&2
***Required*** command not found: python3

If pyenv is installed, you can install python3 via:

    pyenv install 3.7.4  # update as necessary

See the following links for more information:
* https://github.com/pyenv/pyenv
* https://github.com/pyenv/pyenv-installer

ERROR
    exit 1
  }
}

check_for_poetry() {
  command -v poetry >/dev/null 2>&1 || {
    cat <<ERROR >&2
***Required*** command not found: poetry

This can be installed via:

    curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | POETRY_PREVIEW=1 python

See the following links for more information:
* https://poetry.eustace.io/docs/
* https://github.com/sdispater/poetry

ERROR
    exit 1
  }
}

check_for_python3
check_for_poetry
