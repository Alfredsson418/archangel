# Tests and Verification

This guide describes the automated tests currently in the repository, how to run them, and what a successful run looks like. The tests use fixtures and mocks; ordinary test runs do not change the host firewall.

## Prerequisites

- Python 3 and `pip` for the Flask dashboard tests.
- A C++20 compiler and `make` for backend tests.
- `libnftables` development files for building the backend executable with `make debug`.

The GitHub Actions workflow uses Python 3.12 and installs `g++`, `make`, and `libnftables-dev` on Ubuntu.

## Dashboard tests

Create a virtual environment and install the dashboard dependencies:

```sh
python3 -m venv app/web/.venv
app/web/.venv/bin/python -m pip install -r app/web/requirements.txt
```

Run the suite from the dashboard directory:

```sh
cd app/web
.venv/bin/python -m unittest -v
```

The test modules are organized by responsibility:

| Module | Coverage |
| --- | --- |
| `app/web/tests/test_api_client.py` | Backend connectivity and errors, schema-version handling, health checks, and request headers. |
| `app/web/tests/test_dashboard_pages.py` | Server-rendered overview and system pages, log-source rendering and escaping, static assets, and backend-unavailable messaging. |
| `app/web/tests/test_logging.py` | Dashboard and backend request logging, including omission of query-string values. |
| `app/web/tests/test_rules.py` | Firewall status summary, rule rendering/filtering/sorting, structured export, and preview/confirmed import behavior. |
| `app/web/tests/test_settings.py` | API URL settings display, validation, persistence, connection tests, and absence of API passthrough routes. |

Expected result: unittest prints a summary ending in `OK` and exits with status 0. At the time of writing, the suite runs 25 tests. The exact count and incidental application log lines may change as coverage grows.

## Backend tests

Build and run the backend unit tests from the repository root:

```sh
make test
```

The test executable is built at `build/core/tests/backend_tests`. The target compiles it when needed and runs it. Its current test modules cover:

| Module | Coverage |
| --- | --- |
| `core/tests/test_nft_statistics.cpp` | Counts nftables tables, chains, rules, families, protocols, and verdicts; rejects malformed or incorrectly shaped rulesets. |
| `core/tests/test_rules_api.cpp` | Structured rule creation and deletion, input validation and HTTP responses, prevention of backend mutation for invalid requests, and safe handling of backend errors. |

Rule-handler tests use a mock `Firewall`; parser tests use controlled JSON fixtures. They do not start the API server or run nftables commands, and they are not integration tests of the live firewall backend.

Expected result: the command exits with status 0 and prints:

```text
Backend tests passed
```

A failed assertion prints `Backend test failure: ...` and returns a nonzero exit status.

## Build the backend

The unit-test target is separate from the application build. To compile and link the backend executable, run:

```sh
make debug
```

This produces `./archangel` and requires a C++20 compiler plus the `libnftables` development package. A successful build ends with `Done!`. Building the executable does not run tests.

## Continuous integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pushes, pull requests, and manual dispatch. It:

1. Installs the dashboard dependencies and runs the dashboard unittest suite.
2. Installs the C++ build dependencies, runs `make test`, then builds the backend with `make debug`.

The dashboard tests and backend tests/build run as separate jobs. A failure in any command fails its job and the workflow.
