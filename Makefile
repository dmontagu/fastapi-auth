.DEFAULT_GOAL := help
pkg_src = fastapi_auth
tests_src = tests

isort = isort -rc $(pkg_src) $(tests_src)
autoflake = autoflake -r --remove-all-unused-imports --ignore-init-module-imports $(pkg_src) $(tests_src)
black = black $(pkg_src) $(tests_src)
flake8 = flake8 $(pkg_src) $(tests_src)
mypy_base = mypy --show-error-codes
mypy = $(mypy_base) $(pkg_src)
mypy_tests = $(mypy_base) $(pkg_src) $(tests_src)

.PHONY: all  ## Perform the most common development-time rules
all: format lint mypy test

.PHONY: format  ## Auto-format the source code (isort, autoflake, black)
format:
	$(isort)
	$(autoflake) -i
	$(black)

.PHONY: check-format  ## Check the source code format without changes
check-format:
	$(isort) --check-only
	@echo $(autoflake) --check
	@( set -o pipefail; $(autoflake) --check | (grep -v "No issues detected!" || true) )
	$(black) --check

.PHONY: lint  ## Run flake8 over the application source and tests
lint:
	$(flake8)

.PHONY: mypy  ## Run mypy over the application source
mypy:
	$(mypy)

.PHONY: mypy-tests  ## Run mypy over the application source *and* tests
mypy-tests:
	$(mypy_tests)

.PHONY: test  ## Run tests
test:
	pytest --cov=$(pkg_src)

.PHONY: testcov  ## Run tests, generate a coverage report, and open in browser
testcov:
	pytest --cov=$(pkg_src)
	@echo "building coverage html"
	@coverage html
	@echo "opening coverage html in browser"
	@open htmlcov/index.html

.PHONY: static  ## Perform all static checks (format, lint, mypy)
static: format lint mypy

.PHONY: default  ## Run all CI validation steps without making any changes to code
default: test lint mypy check-format

.PHONY: clean  ## Remove temporary and cache files/directories
clean:
	rm -rf `find . -name __pycache__`
	rm -f `find . -type f -name '*.py[co]' `
	rm -f `find . -type f -name '*~' `
	rm -f `find . -type f -name '.*~' `
	rm -rf `find . -type d -name '*.egg-info' `
	rm -rf `find . -type d -name '*.db' `
	rm -rf `find . -type d -name 'pip-wheel-metadata' `
	rm -rf .cache
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf htmlcov
	rm -rf *.egg-info
	rm -f .coverage
	rm -f .coverage.*
	rm -rf build
	rm -rf dist

.PHONY: lock  ## Update the lockfile
lock:
	poetry lock
	poetry export -f requirements.txt >requirements.txt

.PHONY: build  ## Build a wheel
build:
	poetry build

.PHONY: develop  ## Set up the development environment
develop:
	./scripts/check-requirements.sh
	poetry run pip install -r requirements.txt
	poetry install
	@echo "Poetry virtual environment interpreter installed at:"
	@poetry run python -c "import sys; print(sys.executable)"

.PHONY: poetryversion
poetryversion:
	poetry version $(version)

.PHONY: version  ## Bump the version in both pyproject.toml and __init__.py (e.g.; `make version version=minor`)
version: poetryversion
	$(eval NEW_VERS := $(shell cat pyproject.toml | grep "^version = \"*\"" | cut -d'"' -f2))
	@sed -i "" "s/__version__ = .*/__version__ = \"$(NEW_VERS)\"/g" $(pkg_src)/__init__.py

.PHONY: help  ## Display this message
help:
	@grep -E \
		'^.PHONY: .*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ".PHONY: |## "}; {printf "\033[36m%-20s\033[0m %s\n", $$2, $$3}'
