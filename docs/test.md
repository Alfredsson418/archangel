# Tests and Verification

This guide describes the automated tests currently in the repository, how to run them, and what a successful run looks like. The tests use fixtures and mocks; ordinary test runs do not change the host firewall.

## Prerequisites

- Python 3 and `pip` for the Flask dashboard tests.
- A C++20 compiler and `make` for backend tests.
- `libnftables`, SQLite, Argon2, and OpenSSL development files for building and testing backend authentication code.

The GitHub Actions workflow uses Python 3.12 and installs `g++`, `make`, `libnftables-dev`, `libsqlite3-dev`, `libargon2-dev`, and `libssl-dev` on Ubuntu.

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
| `core/tests/test_auth_provider.cpp` | Initial administrator provisioning, normalized and configurable password policy, configurable Argon2id credential verification, API session creation/validation/revocation and expiry, token/password non-persistence, and private SQLite file permissions. |
| `core/tests/test_runtime_config.cpp` | Runtime config defaults and overrides, strict schema/type/value validation, secure file ownership/permissions, missing-file behavior, and symlink rejection. |
| `core/tests/test_http_authentication.cpp` | Default route authentication, public health/login allowlist, Bearer session validation, viewer/operator/admin firewall permissions, login/logout API behavior, and fail-closed storage errors. |
| `core/tests/test_firewall_config.cpp` | Firewall bundle v1 parsing and serialization, ownership-section classification, listener-setting exclusion, round-trip behavior, import-mode semantics, and rejection of invalid ownership/version data. |
| `core/tests/test_nft_import.cpp` | Builds managed-only replacement transactions from fixtures and verifies unmarked rules are not deleted or added. |
| `core/tests/test_nft_statistics.cpp` | Counts nftables tables, chains, rules, families, protocols, and verdicts; rejects malformed or incorrectly shaped rulesets. |
| `core/tests/test_rules_api.cpp` | Structured rule creation and deletion, boundary and invalid-input validation, response codes, prevention of backend mutation for invalid requests, and safe handling of backend errors. |
| `core/tests/test_statistics_api.cpp` | JSON response shape and content type for firewall statistics. |

Authentication tests use isolated temporary SQLite files. Rule-handler tests use a mock `Firewall`; parser tests use controlled JSON fixtures. They do not start the API server or run nftables commands, and they are not integration tests of the live firewall backend.

Expected result: the command exits with status 0 and prints:

```text
Backend tests passed
```

A failed assertion prints `Backend test failure: ...` and returns a nonzero exit status.
The invalid-input tests intentionally trigger `request_rejected code=invalid_request` warning log entries before the success message.

## Build the backend

The unit-test target is separate from the application build. To compile and link the backend executable, run:

```sh
make debug
```

This produces `./archangel` and requires a C++20 compiler plus development packages for libnftables, SQLite, Argon2, and OpenSSL. A successful build ends with `Done!`. Building the executable does not run tests.

## Continuous integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pushes, pull requests, and manual dispatch. It:

1. Installs the dashboard dependencies and runs the dashboard unittest suite.
2. Installs the C++ build dependencies, runs `make test`, then builds the backend with `make debug`.

The dashboard tests and backend tests/build run as separate jobs. A failure in any command fails its job and the workflow.
