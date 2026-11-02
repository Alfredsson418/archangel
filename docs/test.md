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
python3 -m venv dashboard/.venv
dashboard/.venv/bin/python -m pip install -r dashboard/requirements.txt
```

Run the suite from the dashboard directory:

```sh
cd dashboard
.venv/bin/python -m unittest -v
```

The test modules are organized by responsibility:

| Module | Coverage |
| --- | --- |
| `dashboard/tests/test_api_client.py` | `ApiClient` contract tests with a fake transport (schema and bearer headers, schema mismatches, error statuses, invalid JSON, unreachable backend), `UrllibTransport` TLS-context use, request IDs, and failure mapping, and TLS 1.2-minimum certificate verification. |
| `dashboard/tests/test_authentication.py` | Protected pages, login/session rotation, server-side token storage, logout revocation, CSRF, same-origin checks, and safe redirects, and skipping writes for unchanged sessions. |
| `dashboard/tests/test_pages.py` | Server-rendered overview and system pages, log-source rendering and escaping, static assets, backend-unavailable messaging, stopping after the backend is unreachable, redirecting to login when the backend rejects the session, and the unauthenticated `/healthz` probe. |
| `dashboard/tests/test_logging.py` | Stdout and backend request logging without query-string values, owner-only JSONL records with request IDs, reopen after rotation, rejection of shared log files, message structuring, actor ID and outcome fields, `unregistered` in place of unknown paths, and fail-closed `503` for every request except health when the audit log is unavailable. |
| `dashboard/tests/test_rules.py` | Firewall status summary, rule rendering/filtering/sorting, structured export (including the rule shapes nftables actually lists), and preview/confirmed import behavior. |
| `dashboard/tests/test_rule_model.py` | Reading every structured rule shape from nftables listings, including default `reject` options, using shapes taken from real output; rejecting what the form can't represent; rule validation and normalization; bundle versions 1 and 2; plain-language rule descriptions. |
| `dashboard/tests/test_connection_check.py` | Following the dashboard's connection through rulesets: rule order, jumps, multiple base chains, NAT, loopback behavior, and what counts as uncertain. |
| `dashboard/tests/test_firewall_changes.py` | The rule form, ordering rules, tables and chains and their typed confirmations, the review page and its `before -> new` list, management-risk flags, warnings, confirmations, every error outcome when applying, storage and expiry of pending changes, and that logs omit rule contents. |
| `dashboard/tests/test_settings.py` | Read-only API URL display, API URL validation, deployment-fixed API settings and CA bundle checks, plaintext-remote warnings, and absence of API passthrough routes. |

Expected result: unittest prints a summary ending in `OK` and exits with status 0. At the time of writing, the suite runs 246 tests. The exact count and incidental application log lines may change as coverage grows.


## Dashboard, API, and nftables together

This check starts the real backend, signs in through the real dashboard code, and applies real changes: collecting and applying a list, detecting a change made outside Archangel, all-or-nothing failures, a change nftables itself rejects, 1,000 changes at once, editing, ordering, chains, tables, and confirmations. The page scripts are covered by the browser check below. It needs a debug build from `make debug`, and needs no root privileges.

```sh
unshare -rn dashboard/.venv/bin/python dashboard/tests/integration/changes_namespace.py
```

`unshare -rn` gives it a private user and network namespace, so it can't change the host's firewall, and the script refuses to run outside one. It isn't part of the ordinary test suites, but CI runs it. Run it after changing how changes are applied.

Expected result: the command exits with status 0 and ends with `0 failures`.

## In a real browser

This check drives the dashboard in headless Chromium against the real backend and nftables: the rules tree, dragging a rule and applying the result, the arrow buttons, the organize page, phone layout, and use without JavaScript. It's the only check that runs the page scripts. It needs a debug build from `make debug`, and Playwright:

```sh
dashboard/.venv/bin/python -m pip install playwright
dashboard/.venv/bin/python -m playwright install chromium-headless-shell
unshare -rn dashboard/.venv/bin/python dashboard/tests/integration/browser_namespace.py [screenshot-directory]
```

`unshare -rn` gives it a private user and network namespace, so it can't change the host's firewall, and the script refuses to run outside one. It isn't part of CI, and Playwright isn't a dashboard dependency. Run it after changing `dashboard/static/`, the rules page, or the organize page. It uses mouse events, so it doesn't prove touch dragging, which needs checking on a real device.

Expected result: the command exits with status 0 and ends with `0 failures`.

## Connection check against real connections

`dashboard/tests/test_connection_check.py` uses fixtures, which can't prove what nftables really does. This separate check applies real rulesets and makes real TCP connections, from another network namespace and over loopback, then requires the connection check to agree. It needs `nft`, `ip`, `unshare`, and `nsenter`, and needs no root privileges.

```sh
unshare -rn dashboard/.venv/bin/python dashboard/tests/integration/connection_check_namespace.py
```

`unshare -rn` gives it a private user and network namespace, so it can't change the host's firewall, and the script refuses to run outside one. It isn't part of the ordinary test suites, but CI runs it. Run it after changing `dashboard/webapp/connection_check.py`.

Expected result: the command exits with status 0 and ends with `0 failures`.
## Backend tests

Build and run the backend unit tests from the repository root:

```sh
make test
```

The test executable is built at `build/backend/tests/backend_tests`. The target compiles it when needed and runs it. Its current test modules cover:

| Module | Coverage |
| --- | --- |
| `backend/tests/test_auth_provider.cpp` | Initial administrator provisioning, normalized and configurable password policy, configurable Argon2id credential verification, API session creation/validation/revocation and expiry, account creation/update/disable and one-time setup-token lifecycle, administrator recovery, rehashing after an Argon2id cost increase, password-blocklist parsing, file checks, and enforcement, token/password non-persistence, and private SQLite file permissions. |
| `backend/tests/test_runtime_config.cpp` | Runtime config defaults and overrides (including the optional password-blocklist path), strict schema/type/value validation, secure file ownership/permissions, missing-file behavior, and symlink rejection. |
| `backend/tests/test_http_authentication.cpp` | Default route authentication, declared route policies (unregistered routes, duplicate declarations, `HEAD` handling), the public health/login/account-setup allowlist, Bearer session validation, viewer/operator/administrator firewall and account permissions, source/identity/mutation rate limits, bounded rate-limit key tracking, and fail-closed session-storage errors. |
| `backend/tests/test_auth_api.cpp` | Login and logout handlers: Bearer session issuance, rejected credentials and unexpected fields, session revocation, and per-source failed-login throttling with `Retry-After`. |
| `backend/tests/test_accounts_api.cpp` | Account lifecycle handlers: creation with a one-time setup token, unknown-field rejection, listing, role updates, disablement, setup-token reissue, and setup-token redemption. |
| `backend/tests/test_logging.cpp` | JSONL sink envelope, owner-only file and directory creation, rejection of symlinked or shared paths, reopen after rotation, structuring of `event key=value` messages and level filtering, request IDs and audit records, fail-closed `503` when an audit record cannot be written, unregistered-path labeling, shared log-source bounds and redaction, JSONL log rendering, and nftables source states. |
| `backend/tests/test_tls.cpp` | TLS file validation (missing, symlinked, group-readable key, writable certificate), context setup with a matching test-only certificate and key, the TLS 1.2 minimum, and rejection of mismatched or invalid files. |
| `backend/tests/auth_test_support.hpp` | Shared mock `AuthProvider` and schema-header request helper for the three authentication test modules. |
| `backend/tests/test_firewall_bundle.cpp` | Firewall bundle v1 parsing and serialization, ownership-section classification, listener-setting exclusion, round-trip behavior, import-mode semantics, and rejection of invalid ownership/version data. |
| `backend/tests/test_nft_import.cpp` | Builds managed-only replacement transactions from fixtures and verifies unmarked rules are not deleted or added. |
| `backend/tests/test_nft_changes.cpp` | Chain revisions, conflict detection, and building one transaction from a change list without calling nftables. |
| `backend/tests/test_nft_rule.cpp` | Validates structured rules, including subnets with host bits and fields that could never match together, and builds their exact nftables statements without calling nftables. |
| `backend/tests/test_nft_statistics.cpp` | Counts nftables tables, chains, rules, families, protocols, and verdicts; rejects malformed or incorrectly shaped rulesets. |
| `backend/tests/test_rules_api.cpp` | Structured rule creation and deletion, change lists and their bounds and error mapping, the full rule model, rejection of unknown fields, boundary and invalid-input validation, response codes, prevention of backend mutation for invalid requests, and safe handling of backend errors. |
| `backend/tests/test_status_api.cpp` | The connection details and other fields returned by `/status/info`. |
| `backend/tests/test_stats_api.cpp` | JSON response shape and content type for firewall statistics. |

Authentication tests use isolated temporary SQLite files. Rule-handler tests use a mock `Firewall::Backend`; parser tests use controlled JSON fixtures. They do not start the API server or run nftables commands, and they are not integration tests of the live firewall backend.

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

This produces `bin/archangel` and requires a C++20 compiler plus development packages for libnftables, SQLite, Argon2, and OpenSSL. A successful build ends with `Done!`. Building the executable does not run tests.

## Continuous integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pushes, pull requests, and manual dispatch. It:

1. Checks that every C++ source under `backend/src`, `backend/include`, and `backend/tests` matches `.clang-format`, using clang-format 18 on Ubuntu 24.04. The vendored `backend/lib` is not checked.
2. Installs the dashboard dependencies and runs the dashboard unittest suite.
3. Installs the C++ build dependencies, runs `make test`, then builds the backend with `make debug`.

Run the same formatting check locally before pushing; a different clang-format major version may format some constructs differently:

```sh
find backend/src backend/include backend/tests \( -name '*.cpp' -o -name '*.hpp' \) -print0 \
  | xargs -0 clang-format --dry-run --Werror
```

To fix reported files, run `clang-format -i` on them. Formatting-only commits are listed in `.git-blame-ignore-revs`; enable it with `git config blame.ignoreRevsFile .git-blame-ignore-revs`.

The formatting check, dashboard tests, and backend tests/build run as separate jobs. A failure in any command fails its job and the workflow.
