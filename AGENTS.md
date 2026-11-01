# Coding Agent Instructions

## Source of truth

- This file contains repository-specific instructions for coding agents. It is not the source of truth for the product overview, API contract, security posture, roadmap, or test catalog; use the linked reader-facing documents for those.
- Read [architecture.md](docs/architecture.md) before changing service boundaries or module ownership, [frontend-design.md](docs/frontend-design.md) before changing dashboard presentation, [endpoints.md](docs/endpoints.md) before changing API behavior, [security-concerns.md](docs/security-concerns.md) before network/security changes, and [roadmap.md](docs/roadmap.md) before implementing planned work.
- Keep documentation synchronized with code. Update only the relevant documents: API contract in `docs/endpoints.md`; current security posture in `docs/security-concerns.md`; planned work/design decisions in `docs/roadmap.md`; build/test coverage and commands in `docs/test.md`; project overview or run instructions in `README.md`; purpose/vision in `docs/goal.md`.

## Architecture guardrails

- Preserve the service and module boundaries described in [architecture.md](docs/architecture.md). In particular, register C++ API routes only in `core/src/http/server.cpp`; keep handlers in `core/src/http/api/`, backend operations behind the `Firewall` interface, and HTTP validation/serialization at the API boundary.
- Favor replaceable implementations for components with meaningful alternative backends or a committed need to support them. Define a narrow, backend-neutral contract around domain behavior; keep vendor/technology-specific code inside the implementation; select implementations at the composition/configuration boundary; and test contract behavior independently of concrete implementations. Do not spread backend-specific conditionals through handlers or domain logic.
- Do not add interfaces, plugin loading, or generalized frameworks solely for hypothetical future flexibility. First identify a real alternative, portability requirement, or planned provider/sink, and keep abstractions proportional to that need.
- Keep the dashboard server-rendered and server-side when it calls the C++ API; do not add API passthrough routes or duplicate backend identities in Flask/the browser. Any future authentication and authorization must be enforced by the C++ API.
- Keep backend runtime settings separate from firewall import/export. Firewall imports are explicit, privileged operations; do not cause them to run implicitly at service startup.
- Keep structured firewall inputs and preserve the `Firewall` abstraction. Do not execute raw nftables commands built from request data.

## Security and operations

- Treat both services as unauthenticated unless the implementation and [security-concerns.md](docs/security-concerns.md) explicitly show otherwise. Do not recommend exposing them publicly.
- Never run mutating API requests or firewall-changing operations against a live host unless the user explicitly authorizes it and the environment is an appropriate test system.
- Ask the user before choosing among materially different security designs that affect trust boundaries, credentials, authorization, deployment, or operational burden.
- Do not log request/response bodies, query strings, submitted values, credentials, tokens, secrets, or raw firewall-rule input. Use safe event summaries and follow existing logging patterns.
- Keep local settings and secrets out of source control; validate configuration before use.

## Implementation conventions

- Follow `.clang-format` for C++; use four spaces for Python. Do not put application code in generated directories such as `build/`, `.venv/`, or `__pycache__/`.
- Keep responsibilities cohesive and use existing module boundaries. Add new C++ implementations under the matching `core/src/` subsystem with public declarations under `core/include/`; keep implementation-only helpers private where practical.
- Keep API parsing and validation in API handlers, backend behavior behind its interface, and serialization/status codes at the API boundary. Test observable contract changes.
- Document public or cross-module declarations immediately above the declaration, including purpose and return behavior. Python functions should have docstrings describing return shape and relevant exceptions. Document non-obvious private helpers when needed.
- Add concise comments only when they explain non-obvious behavior or rationale; do not restate the code.

## Verification

- Follow [docs/test.md](docs/test.md) for prerequisites, test commands, coverage, and expected output.
- Run the focused applicable tests: dashboard tests for dashboard changes; `make test` and `make debug` for C++ changes. Report checks that could not be run and why.
