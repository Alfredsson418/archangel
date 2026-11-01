# Architecture

Archangel currently consists of two independently deployable services: a privileged C++ firewall API and a Flask dashboard. This document describes the implemented boundaries and points to the contracts and plans that define their behavior.

## Services and deployment

- **Primary platform:** Archangel is primarily designed and developed for Linux, including the C++ firewall service's current nftables integration and host metrics. Other operating systems may be supported in the future, but cross-platform support is not a current priority or compatibility commitment.
- **C++ API:** The `archangel` binary runs on the server whose firewall it manages. It exposes the firewall and system APIs and uses nftables through the backend abstraction.
- **Flask dashboard:** The web application renders HTML and calls the C++ API from the server. It does not expose API passthrough routes. It can run on a separate management computer and must be configured with a reachable API address; a dashboard container's loopback address is not the managed server.
- **Network boundary:** The C++ API authenticates protected requests and enforces firewall roles; the Flask dashboard does not yet integrate the backend login/session contract. The services currently use HTTP and the API does not provide built-in TLS. Keep access on localhost or a trusted, isolated management network. See [security concerns](security-concerns.md) for the current posture and planned controls.
- **Deployment examples:** The Docker Compose setup is a same-host development setup. Separate-host deployments require explicit network configuration and must not be treated as secure merely because Docker is used.

The API routes and JSON payloads are the integration contract. API calls use the `X-Archangel-Schema-Version` header, except bodyless `GET /status/health`. See [endpoints.md](endpoints.md) for the route and payload details.

## Future centralized backend management

The long-term mesh direction includes an Archangel backend acting as a centralized management server for multiple peer backends, so an operator can manage a network from one instance. This is not implemented. Each peer must have an explicit identity and authorization relationship; centralized management must not be treated as implicit trust or as a replacement for authorization enforced by each managed backend.

Peer enrollment is intended to begin with an enrollment token that bootstraps a backend identity and credentials for ongoing authenticated peer communication. The token is not intended to serve as a permanent peer credential. Token issuance, scope/binding, delivery, expiration, redemption and revocation rules, peer credential rotation, secure transport, and management-server failure or compromise behavior remain open design decisions. See the [project goal](goal.md) and [roadmap](roadmap.md) for the broader vision and open questions.

## Backend layout

| Area | Responsibility |
| --- | --- |
| `core/src/main.cpp` | Minimal process entry point delegating to `runApplication`. |
| `core/include/app/application.hpp`, `core/src/app/application.cpp` | CLI setup, command workflows, configuration overrides, dependency construction, and service startup. |
| `core/include/config/app_config.hpp` | Central application settings object and built-in defaults. |
| `core/include/config/runtime_config.hpp` | Runtime JSON parser and protected-file loader contract. |
| `core/src/config/runtime_config.cpp` | Strict runtime JSON parsing, effective-setting validation, and protected-file loading. |
| `core/src/cli/firewall_config.cpp` | CLI support for firewall config bundle file I/O and optional backend capability checks. |
| `core/src/network/address.cpp` | Network address classification used to warn about non-loopback listeners. |
| `core/src/http/server.cpp` | Registration of API routes and wiring routes to handlers. |
| `core/src/http/api/` | Request parsing/validation, backend calls, and HTTP response handling. |
| `core/include/http/api/` | Public declarations corresponding to API handler modules. |
| `core/include/firewall/providers/firewall.hpp` | Backend-neutral firewall interface and shared rule/statistics types. |
| `core/include/firewall/config.hpp` | Portable versioned firewall-bundle schema, parser, and serializer. |
| `core/include/firewall/providers/firewall_config_provider.hpp` | Optional capability for native firewall configuration import/export. |
| `core/include/firewall/providers/`, `core/src/firewall/providers/` | Firewall provider contracts and implementations, including nftables-specific operations. |
| `core/src/firewall/config.cpp` | Firewall-bundle schema validation, parsing, and serialization. |
| `core/include/auth/providers/`, `core/src/auth/providers/` | Backend-owned authentication provider contracts and implementations, currently SQLite/Argon2id. |
| `core/include/auth/`, `core/src/auth/` | Authentication domain utilities, isolated SQLite storage/migration and cryptographic/password helpers, and protected secret input. |
| `core/include/logger.hpp`, `core/src/logger.cpp` | Logging interface and implementation. |
| `core/src/logs/` | Bounded backend log-source readers and redaction, separate from HTTP response serialization. |
| `core/include/` | Public declarations arranged to mirror the source areas. |

The HTTP server and API handlers depend on the `Firewall` interface rather than a concrete firewall implementation. Backend selection belongs at the startup/composition boundary. Backend-specific commands, parsing, resource management, and synchronization stay inside the corresponding implementation. Request validation and HTTP response serialization stay at the API boundary.

The backend version is the Git commit hash embedded in the binary during the build. `/status/info` reports that embedded value; it does not query Git at runtime.

## Replaceable implementations

Where a capability has a real alternative implementation or a defined need to support one, keep the application dependent on a small domain contract rather than a concrete technology. Implementations should own technology-specific operations and data conversion; select them at startup or configuration boundaries. Shared request/response and domain types should not expose vendor-specific details. Keep tests focused on the contract and use fakes where integration with a real service or host would be unsafe or unavailable.

Provider contracts and implementations are grouped in `providers/` beneath their owning domain layers. The firewall is structured this way: API code uses the backend-neutral `Firewall` contract, while nftables-specific operations live in the nftables provider implementation. Native firewall config import/export is an optional `FirewallConfigProvider` capability rather than part of `Firewall`; backends that cannot consume the native bundle do not need to implement it. The CLI checks for the capability and reports unsupported use. The backend-owned `AuthProvider` contract and SQLite/Argon2id local provider are also implemented and used by global API authentication middleware. All routes require a valid session by default except health and login; firewall mutation routes additionally require Operator or Administrator roles. Per-source login-attempt limiting is implemented; dashboard login/token integration and general API rate limiting remain incomplete.

- **Authentication providers and logging sinks:** Local accounts use SQLite and Argon2id behind `AuthProvider`. SQLite file safety, connection ownership, and migrations are separated from provider-level login/session workflows; password hashing, token generation, and username validation are isolated in auth cryptographic helpers. The API login/logout contract, session validation, default authentication, firewall mutation role enforcement, and per-source login-attempt limiting are implemented. Phase 2 still needs dashboard login/token integration and general API rate limiting. Logging-sink contracts and initial JSONL file sinks are planned, not implemented. Keep backend and dashboard sinks independently configured; OIDC and alternate sinks remain future implementations behind the provider contract.
- **Log sources:** A backend log-source module reads the Archangel application log and nftables packet logs, bounds and redacts entries, and returns source data independently of HTTP response serialization. The API handler maps those source records into the JSON contract.
- **System metrics:** The current collector reads Linux-specific sources such as `/proc` and `statvfs`. Phase 4 will introduce a platform-neutral system-information provider contract, initially implemented by the existing Linux collector. This keeps a path open for future operating-system providers but does not make non-Linux support a current priority or commitment.
- **Dashboard API and settings:** The API client and settings module are current boundaries but are not yet replaceable contracts. Phase 2 will formalize a narrow HTTP transport contract and an API-settings provider contract. Preserve the current JSON-file settings provider for the existing unauthenticated workflow; the secured deployment uses a deployment-config provider through `ARCHANGEL_API_URL`, not a browser-editable destination. This prevents user-controlled redirection of backend-held credentials. Keep deployment-specific configuration separate from credential/session storage.

Select implementations at startup or configuration boundaries. Avoid plugin loading or generalized frameworks; compile-time implementations selected at composition time are sufficient for the currently planned backends. Contract tests should exercise behavior independently of concrete implementations, using fakes where integration with a real service or host would be unsafe or unavailable.

## Dashboard layout

| Area | Responsibility |
| --- | --- |
| `app/web/server.py` | WSGI entry point. |
| `app/web/webapp/` | Flask app factory, page views, API client, settings persistence, and logging configuration. |
| `app/web/templates/` | Server-rendered Jinja templates. Page templates extend `base.html`. |
| `app/web/static/` | Shared frontend assets such as stylesheets. |
| `app/web/tests/` | Dashboard tests grouped by responsibility. |

The dashboard uses ordinary HTTP form submissions and server-rendered HTML. Page-specific content belongs in the relevant template, not a duplicated layout. Dashboard pages that need backend data call the configured C++ API from Flask.

See the [frontend design guide](frontend-design.md) for visual and accessibility guidance.

## Firewall configuration formats

There are two distinct configuration workflows:

- The backend CLI's versioned firewall config bundle contains the complete native nftables JSON ruleset and no runtime listener settings. Firewall bundle v1 (`archangel-firewall-config`) distinguishes rules marked with the reserved `archangel-managed` comment from other rules and nftables objects. Imports require an explicit mode: `merge`, managed-only `replace`, or full-ruleset `replace-all`.
- The dashboard's portable structured-rule bundle contains only rules representable by the structured API. It validates and previews imports, then applies rules additively and non-atomically; exports disclose unsupported rules omitted from the bundle.

Neither format is an implicit boot-time restore mechanism. The CLI firewall config must not be conflated with the separate backend runtime settings file documented in the [runtime config guide](runtime-config.md). See [endpoints.md](endpoints.md) for current request and bundle contracts, and [security concerns](security-concerns.md) before changing privileged firewall behavior.

## Related documentation

- [Project overview and quickstart](../README.md)
- [Project goal and broader vision](goal.md)
- [API and dashboard endpoints](endpoints.md)
- [Current security posture and planned controls](security-concerns.md)
- [Development roadmap](roadmap.md)
- [Tests and verification](test.md)
