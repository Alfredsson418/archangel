# Development Guidelines

These conventions apply to all code changes in Archangel. They complement the [architecture](architecture.md), which defines service and module boundaries, the [frontend design guide](frontend-design.md), and the [security concerns](security-concerns.md), which define the current security posture and design principles.

## Code organization

- Keep responsibilities cohesive. Prefer extending an existing module or shared helper over duplicating behavior, and keep interfaces between layers narrow and clear.
- Extract an abstraction when it removes real duplication or clarifies a boundary. Avoid indirection that makes simple code harder to follow.
- Keep source files focused and reasonably small, with one clear responsibility per module. Split a file when it accumulates distinct responsibilities or becomes hard to navigate, and place extracted code in the matching existing subsystem. Do not split code into tiny files only to meet a line count.
- Place C++ implementation files under the matching `core/src/` subsystem and public declarations under the corresponding `core/include/` path. Keep implementation-only helpers private to their `.cpp` file where practical.
- Include public headers by their path under `core/include` and vendored libraries by their path under `core/lib`, for example `#include "http/server.hpp"` or `#include "json/json.hpp"`; the makefile adds both roots. Include private headers that live beside sources in `core/src` by their path relative to the including file.
- Put each C++ subsystem directory's declarations in one namespace named after it: `App`, `Auth`, `Cli`, `Config`, `Firewall`, `Http`, `Logs`, and `Network`. Put private helpers shared between files in a nested `Detail` namespace and file-local helpers in an anonymous namespace inside it. Do not repeat the namespace in a name declared inside it, for example `Firewall::Bundle` rather than `Firewall::FirewallBundle`; the firewall contract is `Firewall::Backend` because a class cannot share its namespace's name. Contracts live at the root of their subsystem and implementations in its `providers/` directory.
- Place dashboard modules in `app/web/webapp/` by responsibility, templates in `app/web/templates/`, shared browser assets in `app/web/static/`, and tests in `app/web/tests/`. Do not add another top-level application directory for functionality that belongs in these areas.
- Keep a function in the module responsible for its behavior and call it from other modules through the appropriate declaration. Do not create duplicate implementations.
- Extend the `Firewall::Backend` contract only when a capability is needed across the API and backend boundary, and update every implementation when its virtual contract changes.

## Limits, bounds, and defaults

- Define each backend limit, bound, and built-in default exactly once in [`core/include/config/app_config.hpp`](../core/include/config/app_config.hpp): limits in `Config::Limits`, and defaults such as paths and session lifetimes in `Config::Defaults` or the `AppConfig` settings object. This covers values such as password, username, and token lengths; Argon2id bounds; request-body and file-size limits; log-read bounds; lifetimes; and rate-limit and tracking bounds.
- Reference these constants wherever the value is needed, including in validation, error messages, and documentation comments. Do not add local `constexpr` copies or repeat the value as a literal.
- Keep format and contract constants with the module that owns them, not in `app_config.hpp`. Examples are the API schema version and header in `core/include/http/api/schema.hpp`, the `archangel-managed` rule marker in `core/include/firewall/bundle.hpp`, the authentication database migration version, and fixed algorithm output sizes.
- In the dashboard, define each limit once as a named module constant and derive form attributes and user-facing text from it rather than repeating the number. When a dashboard value mirrors a backend limit, name the backend constant it mirrors in a comment; the backend remains authoritative.

## Documentation comments

- Document public or cross-module declarations immediately above the declaration, with their purpose and an explicit return description, including when a function returns no value. Include parameters and exceptions when they are part of the contract.
- Give Python functions docstrings that describe the return shape and relevant exceptions.
- Comment non-obvious code with both the mechanism and the reason it achieves the intended behavior. Do not add comments that restate straightforward code, and update comments when behavior changes.

## Logging

- Log at meaningful operational boundaries: service startup and failure, request method and path, response status and duration, backend API call outcomes, validation rejections, configuration changes, and firewall operation success or failure.
- Include enough non-sensitive context to diagnose failures, such as operation name, error category, status, and duration. Log unexpected exceptions with appropriate severity, and do not swallow them silently.
- Never log request or response bodies, query-string values, submitted form values, credentials, tokens, secrets, or raw firewall-rule input; log safe event summaries instead.
- Follow the existing conventions in `core/include/logs/logger.hpp` and `app/web/webapp/audit_log.py`.

## Keeping documentation synchronized

Update only the documents relevant to a change:

| Change | Document |
| --- | --- |
| Project overview, build, or run instructions | [README.md](../README.md) |
| Purpose or long-term direction | [goal.md](goal.md) |
| Service or module boundaries, layout, or ownership | [architecture.md](architecture.md) |
| Dashboard presentation | [frontend-design.md](frontend-design.md) |
| Routes, payloads, status codes, or bundle semantics | [endpoints.md](endpoints.md) |
| Runtime configuration fields, defaults, or precedence | [runtime-config.md](runtime-config.md) |
| Current security posture or planned controls | [security-concerns.md](security-concerns.md) |
| Vulnerability-reporting process | [SECURITY.md](../SECURITY.md) |
| Planned work, status, exit criteria, or design decisions | [roadmap.md](roadmap.md) |
| Test suites, commands, prerequisites, or expected output | [test.md](test.md) |
| Coding conventions | this document |
| Contribution or conduct process | [CONTRIBUTING.md](../CONTRIBUTING.md), [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) |

Keep these documents reader-facing. Add new documents to this table and to the related-documentation list in [architecture.md](architecture.md).
