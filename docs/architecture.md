# Architecture

Archangel currently consists of two independently deployable services: a privileged C++ firewall API and a Flask dashboard. This document describes the implemented boundaries and points to the contracts and plans that define their behavior.

## Services and deployment

- **Primary platform:** Archangel is primarily designed and developed for Linux, including the C++ firewall service's current nftables integration and host metrics. Other operating systems may be supported in the future, but cross-platform support is not a current priority or compatibility commitment.
- **C++ API:** The `archangel` binary runs on the server whose firewall it manages. It exposes the firewall and system APIs and uses nftables through the backend abstraction.
- **Flask dashboard:** The web application renders HTML and calls the C++ API from the server. It does not expose API passthrough routes. It can run on a separate management computer and must be configured with a reachable API address; a dashboard container's loopback address is not the managed server.
- **Network boundary:** The C++ API authenticates protected requests and enforces firewall and account-management roles. The Flask dashboard authenticates with the backend and keeps its API session token in an owner-only server-side SQLite session store. The API serves HTTPS when native TLS is enabled, and the dashboard verifies its certificate; otherwise traffic is plain HTTP. Keep access on localhost or a trusted, isolated management network. See [security concerns](security-concerns.md) for the current posture and planned controls.
- **Deployment examples:** The Docker Compose setup is a same-host development setup. Running the dashboard on the firewall's own host and reaching it from another computer isn't recommended outside development or testing, because firewall changes can then cut off the browser's connection. Separate-host deployments require explicit network configuration and must not be treated as secure merely because Docker is used.

The API routes and JSON payloads are the integration contract. API calls use the `X-Archangel-Schema-Version` header, except bodyless `GET /status/health`. See [endpoints.md](endpoints.md) for the route and payload details.

## Future centralized backend management

The long-term mesh direction includes an Archangel backend acting as a centralized management server for multiple peer backends, so an operator can manage a network from one instance. This is not implemented. Each peer must have an explicit identity and authorization relationship; centralized management must not be treated as implicit trust or as a replacement for authorization enforced by each managed backend.

Peer enrollment is intended to begin with an enrollment token that bootstraps a backend identity and credentials for ongoing authenticated peer communication. The token is not intended to serve as a permanent peer credential. Token issuance, scope/binding, delivery, expiration, redemption and revocation rules, peer credential rotation, secure transport, and management-server failure or compromise behavior are defined in the [mesh design](phases/mesh.md). See the [project goal](goal.md) and [roadmap](roadmap.md) for the broader vision and open questions.

## Backend layout

| Area | Responsibility |
| --- | --- |
| `backend/src/main.cpp` | Minimal process entry point delegating to `App::runApplication`. |
| `backend/include/app/application.hpp`, `backend/src/app/application.cpp` | CLI setup, command workflows, configuration overrides, dependency construction, and service startup. |
| `backend/include/config/app_config.hpp` | Central application settings object, built-in defaults, and the single definitions of backend limits (`Config::Limits`), such as password, username, token, Argon2id, request-body, file-size, log-read, and rate-limiter bounds. Modules reference these instead of keeping local copies; format and contract constants such as the API schema version stay with their owners. |
| `backend/include/config/runtime_config.hpp` | Runtime JSON parser and protected-file loader contract. |
| `backend/src/config/runtime_config.cpp` | Strict runtime JSON parsing, effective-setting validation, and protected-file loading. |
| `backend/src/cli/firewall_bundle_command.cpp` | CLI support for firewall config bundle file I/O and optional backend capability checks. |
| `backend/src/network/address.cpp` | Network address classification used to warn about non-loopback listeners. |
| `backend/src/http/server.cpp` | Registration of API routes and wiring routes to handlers. |
| `backend/src/http/api/` | Request parsing/validation, backend calls, and HTTP response handling. |
| `backend/include/http/api/` | Public declarations corresponding to API handler modules. |
| `backend/include/firewall/firewall.hpp` | Backend-neutral firewall interface and shared rule/statistics types. |
| `backend/include/firewall/bundle.hpp` | Portable versioned firewall-bundle schema, parser, and serializer. |
| `backend/include/firewall/firewall_bundle_provider.hpp` | Optional capability for native firewall bundle import/export. |
| `backend/include/firewall/providers/`, `backend/src/firewall/providers/` | Firewall implementations, currently nftables, with their private parsing and import helpers. |
| `backend/src/firewall/bundle.cpp` | Firewall-bundle schema validation, parsing, and serialization. |
| `backend/include/auth/auth_provider.hpp` | Backend-owned authentication contract and identity, session, and account types. |
| `backend/include/auth/providers/`, `backend/src/auth/providers/` | Authentication implementations, currently SQLite/Argon2id, with its private storage and migration code. |
| `backend/include/auth/`, `backend/src/auth/` | Provider-independent authentication helpers: password hashing and tokens, the password blocklist, and protected secret input. |
| `backend/include/logs/logger.hpp`, `backend/src/logs/logger.cpp` | Logging interface and implementation. |
| `backend/include/logs/log_sink.hpp`, `log_source.hpp` | Contracts for writing log records and for reading the sources returned by `GET /api/v1/logs`. |
| `backend/include/logs/providers/`, `backend/src/logs/providers/` | Log sink and source implementations. |
| `backend/src/logs/log_sources.cpp` | Shared bounds and redaction applied to every log source, separate from HTTP response serialization. |
| `backend/include/http/api/error.hpp` | API error types carrying an HTTP status and stable error code; used only by the HTTP layer. |
| `backend/include/` | Public declarations arranged to mirror the source areas. |

The HTTP server and API handlers depend on the `Firewall::Backend` interface rather than a concrete firewall implementation. Backend selection belongs at the startup/composition boundary. Backend-specific commands, parsing, resource management, and synchronization stay inside the corresponding implementation. Request validation and HTTP response serialization stay at the API boundary.

The backend version is the Git commit hash embedded in the binary during the build. `/status/info` reports that embedded value; it does not query Git at runtime.

## Replaceable implementations

Where a capability has a real alternative implementation or a defined need to support one, keep the application dependent on a small domain contract rather than a concrete technology. Implementations should own technology-specific operations and data conversion; select them at startup or configuration boundaries. Shared request/response and domain types should not expose vendor-specific details. Keep tests focused on the contract and use fakes where integration with a real service or host would be unsafe or unavailable.

Each contract lives at the root of its owning domain, for example `firewall/firewall.hpp`, `auth/auth_provider.hpp`, and `logs/log_sink.hpp`, and its implementations live in that domain's `providers/` directory. Contracts and domain code never include a provider header; only the composition code in `backend/src/app/` and the implementation's own tests do. Domain errors are domain types, such as `InvalidRuleError` and `AccountOperationError`; the HTTP layer maps them to statuses, so implementations never depend on HTTP types. The firewall is structured this way: API code uses the backend-neutral `Firewall::Backend` contract, while nftables-specific operations live in the nftables provider implementation. Native firewall config import/export is an optional `Firewall::BundleProvider` capability rather than part of `Firewall::Backend`; backends that cannot consume the native bundle do not need to implement it. The CLI checks for the capability and reports unsupported use. The backend-owned `AuthProvider` contract and SQLite/Argon2id local provider are also implemented and used by global API authentication middleware. All routes require a valid session by default except health, login, and one-time account setup; firewall mutation routes require Operator or Administrator, and account-management routes require Administrator. The dashboard login/token integration, CSRF protections, and source/identity API and firewall-mutation rate limits are implemented.

- **Authentication providers and logging sinks:** Local accounts use SQLite and Argon2id behind `AuthProvider`. SQLite file safety, connection ownership, and migrations are separated from provider-level login/session workflows; password hashing, token generation, and username validation are isolated in auth cryptographic helpers. The API login/logout/account lifecycle contract, session validation, default authentication, role enforcement, and configured login/API/firewall-mutation rate limits are implemented. The Flask dashboard uses a separate server-side SQLite session store and sends the backend credential with protected API calls. The backend writes structured records through the `LogSink` contract; `JsonlFileSink` appends them to an owner-only JSONL file, and request audit records fail closed when they cannot be written. Keep backend and dashboard sinks independently configured; OIDC and alternate sinks remain future implementations behind the provider contract.
- **Log sources:** Each source returned by `GET /api/v1/logs` implements the `LogSource` contract: `ApplicationLogSource` reads the backend JSONL log and `NftablesJournalSource` reads nftables packet logs from the kernel journal. `readLogSources` applies the shared entry limits, line truncation, and redaction to every source, and the API handler maps the results into the JSON contract. Sources are built at startup in `backend/src/app/`. Keep logs grouped by independently identified sources: each source reports its availability and a safe explanation when unavailable, returns a bounded number of entries, and redacts common secrets. Do not read arbitrary host paths or return the entire system journal. Add new sources through the backend log-source module and API contract, and render them through the dashboard's generic source-based logs page rather than source-specific pages.
- **System metrics:** The current collector reads Linux-specific sources such as `/proc` and `statvfs`. Phase 4 will introduce a platform-neutral system-information provider contract, initially implemented by the existing Linux collector. This keeps a path open for future operating-system providers but does not make non-Linux support a current priority or commitment.
- **Dashboard API and settings:** `ApiClient` adds schema checks, logging, and request-ID handling on top of the `ApiTransport` contract; `UrllibTransport` implements it with certificate verification, and tests use a fake transport. `load_api_settings` provides the deployment-fixed `ApiSettings`. The API destination comes only from the deployment through `ARCHANGEL_API_URL` (defaulting to `http://127.0.0.1:8080`), not from a settings file or a browser-editable value. This prevents user-controlled redirection of backend-held credentials. An optional `ARCHANGEL_API_CA_BUNDLE` adds a private CA to the system trust store. Keep deployment-specific configuration separate from credential/session storage.

Select implementations at startup or configuration boundaries. Avoid plugin loading or generalized frameworks; compile-time implementations selected at composition time are sufficient for the currently planned backends. Contract tests should exercise behavior independently of concrete implementations, using fakes where integration with a real service or host would be unsafe or unavailable.

### Selecting an implementation

Each contract currently has one implementation, so the composition layer in `backend/src/app/application.cpp` constructs it directly: `Firewall::Nftables` for `Firewall::Backend` and `SqliteAuthProvider` for `AuthProvider`. The runtime config already names the authentication provider (`auth.provider`, which accepts only `local`); there is no firewall setting while nftables is the only backend, because a choice with one option adds configuration without value. When a contract gains a second implementation:

- **Name the choice in the runtime config.** Add a setting such as `firewall.backend`, alongside `auth.provider`, with a documented default. Validate it against the implementations compiled into the binary and fail startup on an unknown or unavailable value; never fall back silently to a different backend.
- **Construct it in one factory.** Map the setting to an implementation in a single factory function in `backend/src/app/` that returns the contract type, for example `std::unique_ptr<Firewall>`. No other module names a concrete implementation or branches on the configured value.
- **Detect optional capabilities on the instance.** Check the selected object for optional contracts, as `Cli::requireBundleProvider` does with `dynamic_cast<Firewall::BundleProvider *>`, and report unsupported use clearly. Do not infer capabilities from the configured name.
- **Keep implementation settings separate.** Put settings specific to one implementation in its own config section and pass them to it from the factory; shared code never reads them.
- **Test the contract once for every implementation.** Run a shared contract test suite against each implementation and against a test fake, and give implementation-specific behavior, such as nftables JSON parsing, its own tests. Tests that need a privileged host or live firewall stay out of `make test`.
- **Document it.** Describe the setting in the [runtime config guide](runtime-config.md) and the implementation in this document.

The same rules apply when an OIDC provider is added behind `auth.provider`.

## Dashboard layout

| Area | Responsibility |
| --- | --- |
| `dashboard/server.py` | WSGI entry point. |
| `dashboard/webapp/__init__.py` | Flask app factory: configuration, session store, CSRF and login guards. |
| `dashboard/webapp/views.py` | Page routes and their request handling. |
| `dashboard/webapp/page_data.py` | Loading C++ API resources for pages with the session credential, including expired-session handling. |
| `dashboard/webapp/api_client.py` | HTTP transport to the C++ API and schema-version checks. |
| `dashboard/webapp/firewall_rules.py` | Ruleset inspection and portable rule-bundle conversion and validation; no Flask dependency. |
| `dashboard/webapp/formatting.py` | Display formatting for host and backend metrics. |
| `dashboard/webapp/server_sessions.py`, `settings.py` | Server-side session store and deployment-fixed API settings. |
| `dashboard/webapp/audit_log.py` | Stdout and JSONL audit logging, request IDs, and the fail-closed audit gate for every request except health and static files. |
| `dashboard/templates/` | Server-rendered Jinja templates. Page templates extend `base.html`. |
| `dashboard/static/` | Shared frontend assets such as stylesheets. |
| `dashboard/tests/` | Dashboard tests grouped by responsibility. |

The dashboard uses ordinary HTTP form submissions and server-rendered HTML. Page-specific content belongs in the relevant template, not a duplicated layout. Dashboard pages that need backend data call the configured C++ API from Flask.

The dashboard must not restart, stop, or otherwise control the managed host or the Archangel service directly. Any future operational action must be a backend API operation, authenticated and authorized for that specific action, and limited to an explicitly designed service-manager integration (an open roadmap decision). Until then, system-management pages stay read-only and label unavailable actions clearly, as the disabled restart control does today.

See the [frontend design guide](frontend-design.md) for visual and accessibility guidance.

## Firewall configuration formats

There are two distinct configuration workflows:

- The backend CLI's versioned firewall config bundle contains the complete native nftables JSON ruleset and no runtime listener settings. Firewall bundle v1 (`archangel-firewall-config`) distinguishes rules marked with the reserved `archangel-managed` comment from other rules and nftables objects. Imports require an explicit mode: `merge`, managed-only `replace`, or full-ruleset `replace-all`.
- The dashboard's portable structured-rule bundle contains only rules representable by the structured API. It validates and previews imports, then applies rules additively and non-atomically; exports disclose unsupported rules omitted from the bundle.

Neither format is an implicit boot-time restore mechanism. The CLI firewall config must not be conflated with the separate backend runtime settings file documented in the [runtime config guide](runtime-config.md). See [endpoints.md](endpoints.md) for current request and bundle contracts, and [security concerns](security-concerns.md) before changing privileged firewall behavior.

## Related documentation

- [Project overview and quickstart](../README.md)
- [Project goal and broader vision](goal.md)
- [Development guidelines](development-guidelines.md)
- [Frontend design guide](frontend-design.md)
- [API and dashboard endpoints](endpoints.md)
- [Backend runtime configuration](runtime-config.md)
- [Current security posture and planned controls](security-concerns.md)
- [Development roadmap](roadmap.md)
- [Mesh network design](phases/mesh.md)
- [Phase designs](phases/README.md)
- [Tests and verification](test.md)
