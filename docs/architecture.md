# Architecture

Archangel currently consists of two independently deployable services: a privileged C++ firewall API and a Flask dashboard. This document describes the implemented boundaries and points to the contracts and plans that define their behavior.

## Services and deployment

- **Primary platform:** Archangel is primarily designed and developed for Linux, including the C++ firewall service's current nftables integration and host metrics. Other operating systems may be supported in the future, but cross-platform support is not a current priority or compatibility commitment.
- **C++ API:** The `archangel` binary runs on the server whose firewall it manages. It exposes the firewall and system APIs and uses nftables through the backend abstraction.
- **Flask dashboard:** The web application renders HTML and calls the C++ API from the server. It does not expose API passthrough routes. It can run on a separate management computer and must be configured with a reachable API address; a dashboard container's loopback address is not the managed server.
- **Network boundary:** The services currently use HTTP. Neither service currently provides authentication or authorization, and the API does not provide built-in TLS. Keep access on localhost or a trusted, isolated management network. See [security concerns](security-concerns.md) for the current posture and planned controls.
- **Deployment examples:** The Docker Compose setup is a same-host development setup. Separate-host deployments require explicit network configuration and must not be treated as secure merely because Docker is used.

The API routes and JSON payloads are the integration contract. API calls use the `X-Archangel-Schema-Version` header, except bodyless `GET /status/health`. See [endpoints.md](endpoints.md) for the route and payload details.

## Backend layout

| Area | Responsibility |
| --- | --- |
| `core/src/main.cpp` | Process startup and composition of the service. |
| `core/src/cli.cpp` | Command-line options. |
| `core/src/http/server.cpp` | Registration of API routes and wiring routes to handlers. |
| `core/src/http/api/` | Request parsing/validation, backend calls, and HTTP response handling. |
| `core/include/http/api/` | Public declarations corresponding to API handler modules. |
| `core/include/firewall/firewall.hpp` | Backend-neutral firewall interface and shared rule/statistics types. |
| `core/src/firewall/` | Firewall implementations, including nftables-specific operations. |
| `core/include/` | Public declarations arranged to mirror the source areas. |

The HTTP server and API handlers depend on the `Firewall` interface rather than a concrete firewall implementation. Backend selection belongs at the startup/composition boundary. Backend-specific commands, parsing, resource management, and synchronization stay inside the corresponding implementation. Request validation and HTTP response serialization stay at the API boundary.

The backend version is the Git commit hash embedded in the binary during the build. `/status/info` reports that embedded value; it does not query Git at runtime.

## Replaceable implementations

Where a capability has a real alternative implementation or a defined need to support one, keep the application dependent on a small domain contract rather than a concrete technology. Implementations should own technology-specific operations and data conversion; select them at startup or configuration boundaries. Shared request/response and domain types should not expose vendor-specific details. Keep tests focused on the contract and use fakes where integration with a real service or host would be unsafe or unavailable.

The firewall is already structured this way: API code uses the backend-neutral `Firewall` contract, while nftables-specific operations live in the nftables implementation. The following additional boundaries are selected design requirements, not implemented features:

- **Authentication providers and logging sinks:** Phase 2 introduces backend-owned authentication-provider and service-local logging-sink contracts. SQLite local accounts and JSONL file sinks are the first implementations. Keep backend and dashboard sinks independently configured; OIDC and alternate sinks remain future implementations behind the same contracts.
- **Log sources:** The API log collection handler currently reads the Archangel log file and invokes `journalctl` for nftables packet logs directly. Phase 2 will define a narrow source-reader contract and adapt these existing sources to it. Each source reports availability and a safe explanation, and returns bounded entries that pass through common redaction before exposure.
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

- The backend CLI's versioned JSON config includes bind settings and the complete native nftables JSON ruleset. Config v2 distinguishes rules marked with the reserved `archangel-managed` comment from other rules and nftables objects. Imports require an explicit mode: `merge`, managed-only `replace`, or full-ruleset `replace-all`.
- The dashboard's portable structured-rule bundle contains only rules representable by the structured API. It validates and previews imports, then applies rules additively and non-atomically; exports disclose unsupported rules omitted from the bundle.

Neither format is an implicit boot-time restore mechanism. The CLI firewall config must not be conflated with the separate backend runtime settings file planned in the [roadmap](roadmap.md). See [endpoints.md](endpoints.md) for current request and bundle contracts, and [security concerns](security-concerns.md) before changing privileged firewall behavior.

## Related documentation

- [Project overview and quickstart](../README.md)
- [Project goal and broader vision](goal.md)
- [API and dashboard endpoints](endpoints.md)
- [Current security posture and planned controls](security-concerns.md)
- [Development roadmap](roadmap.md)
- [Tests and verification](test.md)
