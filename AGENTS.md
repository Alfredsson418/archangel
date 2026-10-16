# Project Guidelines

## Architecture

- The C++20 firewall API is in `core/src` with public headers in `core/include`; it uses libnftables and `cpp-httplib`.
- The Flask dashboard is in `app/web`. The browser communicates with Flask over HTTP and receives server-rendered HTML; dashboard forms use normal HTTP form submissions. Flask calls the C++ API server-side and does not expose API passthrough routes.
- Use HTTP for communication between services. The Flask backend and C++ API exchange JSON for API data; the documented C++ `GET /` health endpoint is a plain-text exception. Keep API routes and payloads as the integration contract; do not add a second transport or data format without an explicit architectural change. HTTPS is a planned improvement, not a current API capability guarantee.
- Treat the C++ API backend as the authoritative trust boundary for user identity, authentication, and authorization. The frontend and browser are not trusted to enforce access control; any future authentication or permission checks must be enforced by the backend.
- Keep authentication state and user records authoritative in the backend. Do not create a separate user-authentication database for the Flask dashboard or browser; the frontend should use the backend's authentication contract rather than maintain duplicate identities or credentials.
- Authenticate and authorize every C++ API request independently. Each API call must carry credentials or a verifiable backend-issued credential, and the backend must validate identity and permissions for that call. A frontend login screen or session state alone must never grant access or permit an API request to bypass backend checks.
- Treat the long-term product direction as a frontend administrative tool for configuring and managing backend services, with backend APIs able to communicate with other backends to form a mesh network. This is an aspiration, not a current capability; keep peer identity, trust, authorization, communication protocols, and topology explicit design decisions rather than assuming implicit trust between backends.
- Use the thesis PDF in `assets/` as a source of architectural context, not as proof that proposed components exist or requirements are fully specified. Keep its Zero Trust roles (SG/EG/RG, PDP/PE/PA, PEP, agents, PKI, and security-event services) and staged PoC direction distinct from the implemented code, and do not claim KSF compliance without a deployment-specific assessment.
- Keep the API and dashboard as separate services. See [docs/endpoints.md](docs/endpoints.md) for their routes and payloads.
- Read [docs/goal.md](docs/goal.md) for the project's purpose and intended long-term direction. Treat stated aspirations and unresolved questions there as context, not as already implemented features or fixed technical requirements.

## Source Layout

- `core/src/main.cpp` is the C++ entry point; `core/src/cli.cpp` handles CLI configuration.
- `core/src/http/server.cpp` is the only place that registers/exposes C++ API endpoints and wires routes to handler functions. Keep endpoint implementations in `core/src/http/api/`, with declarations in the corresponding `core/include/http/api/` headers; shared API helpers belong in `api_common.hpp`. Do not register routes in handler or backend files.
- `core/src/firewall/` contains firewall backend implementations. `core/include/firewall/firewall.hpp` defines the backend abstraction and shared rule/statistics types; keep backend-specific nftables operations in `nft.*`.
- `core/include/` mirrors the C++ source areas and holds public declarations. Update the matching header when changing a public interface.
- When adding C++ source, place implementation files under the matching `core/src/` subsystem and public declarations under the corresponding `core/include/` path; keep names and directory structure aligned (for example, `core/src/firewall/<backend>.cpp` and `core/include/firewall/<backend>.hpp`). Keep implementation-only helpers private to the `.cpp` file where practical. Update the build or dependency configuration only when the existing recursive source discovery is insufficient.
- `app/web/server.py` creates the WSGI app. `app/web/webapp/` contains the Flask app factory, page views, API client, settings persistence, and logging configuration.
- `app/web/templates/` contains Jinja templates; page templates extend `base.html`. `app/web/static/` contains shared frontend assets, including `styles.css`.
- Add dashboard modules to `app/web/webapp/` according to their responsibility, templates to `app/web/templates/`, shared browser assets to `app/web/static/`, and focused tests alongside the existing dashboard test layout. Avoid introducing another top-level application directory for functionality that belongs in these existing areas.
- Keep dashboard tests in `app/web/test_server.py` and dependencies in `app/web/requirements.txt`. Do not put application code in generated directories such as `build/`, `.venv/`, or `__pycache__/`.

## Backend Design

- Treat `core/include/firewall/firewall.hpp` as the backend-neutral firewall contract. The HTTP server and API handlers depend on `Firewall`, not on a concrete firewall implementation.
- Implement new firewall technologies as separate implementations of `Firewall` under `core/src/firewall/` with their public declarations under `core/include/firewall/`. Keep vendor-specific headers, commands, parsing, resource management, and synchronization inside that implementation; do not leak them into API handlers or shared backend-neutral types.
- Keep shared rule and statistics data backend-neutral. Extend the abstraction only when a capability is needed across the API and backend boundary; update every implementation when changing its virtual contract.
- Select or construct the concrete backend at the composition/startup boundary (currently `core/src/main.cpp`) and pass it through the existing `Firewall` interface. Do not scatter backend selection or implementation-specific conditionals through routes or unrelated modules.
- Keep HTTP request parsing and validation in `core/src/http/api/`, backend operations behind the interface, and HTTP status/JSON serialization at the API boundary. Document and test observable contract changes.
- Implement user authentication, authorization decisions, and their authoritative user/credential storage in the backend/API layer. Authenticate and authorize each API call; do not rely on the frontend login flow or session state as proof of API access, and do not duplicate user-authentication stores in Flask or the browser. Until this work is implemented, preserve the documented unauthenticated status and deployment restrictions.
- Keep functions in the source module responsible for their behavior and call them from other modules through the appropriate declaration/header, as the route-registration/handler split does today. Avoid putting unrelated function implementations together in `server.cpp` or creating duplicate implementations.

## Frontend Design

- Treat `assets/archangel_poster.png` as the visual identity reference. Use its magenta-to-indigo-to-deep-blue gradient and teal accents selectively, keeping the dashboard's light paper surfaces and dark navy text for readability.
- Reuse the CSS custom properties at the top of `app/web/static/styles.css` rather than introducing one-off colors: `--paper` `#f3f6f8`, `--white` `#fff`, `--ink` `#142b49`, `--muted` `#718096`, `--line` `#d9e2eb`, `--magenta` `#bd1979`, `--indigo` `#643875`, `--blue` `#0e5075`, and `--teal` `#17a6ad`. Keep the sidebar a solid blue and reserve the brand gradient for small accents such as the logo mark.
- Use Manrope for general interface text and DM Mono for compact labels, navigation indexes, table headings, and other data-oriented metadata, as defined by `--sans` and `--mono`.
- Keep the frontend simple and minimalistic: prioritize clear hierarchy, generous enough spacing, restrained typography, and only the controls and decoration needed to understand or use each page. Prefer flat surfaces and fine borders over visual effects; use the brand gradient sparingly as an accent rather than as a large background. Reserve color for emphasis and state, maintain readable contrast, and do not rely on color alone to convey status.
- Support regular 16:9 desktop screens, wider displays, and phones. Use responsive layouts that make sensible use of available width on large screens and remain readable and operable without horizontal page scrolling on narrow screens.
- Preserve accessibility: use semantic HTML and associated form labels, support keyboard navigation, keep visible focus indicators, provide meaningful status text, and ensure responsive layouts work at narrow widths. Do not convey errors or state using color alone.
- Do not implement user authentication or authorization solely in the frontend, and do not maintain a separate dashboard/browser user-authentication database. A login screen is only an interface: every API call must be authenticated and authorized by the backend using credentials or a backend-verifiable credential. Display and submit authentication through the backend's contract when backend authentication is implemented.
- Build pages from the shared `base.html` layout and its Jinja blocks. Put page-specific content in the relevant template instead of duplicating the shell or navigation.

## Build and Test

- Build the C++ API with `make debug`. A C++20 compiler and libnftables development files are required.
- Run dashboard tests from `app/web` with `.venv/bin/python -m unittest` when the project virtual environment is available. Install dependencies from `requirements.txt` if needed.
- There is currently no C++ test target. Do not imply that building the API runs tests.
- For dashboard changes, run the dashboard unittest suite. For C++ changes, build with `make debug`; also run any focused checks that apply. Report checks that could not be run and why.

## Conventions

- Follow `.clang-format` for C++ formatting and use four-space indentation in Python.
- Document non-obvious code so other developers can understand its purpose and logical behavior. For advanced or subtle code, comments should explain both the technical mechanism and why/how it achieves the intended behavior. Prefer concise, accurate comments near the relevant logic; do not add comments that merely restate straightforward code, and keep comments updated when behavior changes.
- Document public or cross-module function declarations immediately above the declaration with a concise purpose and an explicit return description (`@return`, including when a `void` function returns no value). Include parameter and exception details when they are part of the contract. For Python functions, use a docstring with the return shape and relevant exceptions. Document private helpers when their behavior or return contract is not self-evident; keep the documentation synchronized with implementation changes.
- Prioritize modularity and reuse: keep responsibilities cohesive, prefer extending existing modules and shared helpers/components over duplicating behavior, and keep interfaces clear between layers. Extract an abstraction when it removes real duplication or clarifies a boundary; avoid indirection that makes simple code harder to follow.
- Keep source files focused and reasonably small: one clear responsibility per module, with related declarations and implementation in corresponding files. Split a file when it accumulates distinct responsibilities or becomes difficult to navigate; place extracted code in the appropriate existing subsystem and share it through a narrow interface. Do not split code into tiny files solely to meet an arbitrary line limit.
- Preserve the firewall backend abstraction when changing rule handling; keep API validation and HTTP concerns in their existing layers. Validate structured request fields at the API boundary and return consistent HTTP status codes and JSON error responses.
- Keep Markdown documentation reader-facing. Do not put instructions aimed at coding agents, editing workflows, or maintenance tasks in user documentation; put those instructions in this `AGENTS.md`.
- Keep documentation synchronized with the implementation and update only the documents relevant to a change:
  - Update `README.md` when build/run instructions, project overview, or roadmap status changes.
  - Update `docs/endpoints.md` when routes, request/response payloads, status codes, or API behavior change.
  - Update `SECURITY.md` when security behavior, vulnerability-reporting guidance, current security posture, or planned security controls change. Keep planned controls clearly distinct from implemented protections.
  - Update `docs/roadmap.md` when planned work, sequencing, status, exit criteria, or material design decisions change. Keep exploratory ideas distinct from committed work and implemented features.
  - Update `docs/goal.md` when project purpose or long-term architectural direction changes. Keep it descriptive and reader-facing; distinguish implemented capabilities from aspirations and state unresolved assumptions as open questions rather than settled requirements.
  - Update `AGENTS.md` when agent-facing conventions, design rules, source layout, or build/test workflows change. Do not update it for unrelated feature details.
  - Keep this list updated for new documentation files in the future.
- Keep local settings, credentials, and secrets out of source control. Validate configuration values before use.

## Logging

- Add comprehensive, structured logs at meaningful operational boundaries: service startup and shutdown/failure, incoming request method and path, response status and duration, backend API call outcomes, validation rejections, configuration changes, and firewall operation success or failure.
- Include enough non-sensitive context to diagnose failures, such as operation name, error category, status, and duration. Log exceptions with appropriate severity and context; do not silently swallow unexpected failures.
- Never log request or response bodies, query-string values, submitted form values, credentials, tokens, secrets, or other sensitive data. Do not log raw firewall rule input; use safe event summaries instead.
- Follow existing logging conventions in `core/include/logger.hpp` and `app/web/webapp/logging_config.py`. Preserve the dashboard's omission of query strings and form values from request logs.

## Security

- Treat security as a major project concern in all design and implementation work, not as a final add-on. When introducing or changing security controls, assess the CIA triad—confidentiality, integrity, and availability—and apply IAAA access-control principles: identification, authentication, authorization, and accounting. State the relevant threats and tradeoffs, enforce controls at the backend trust boundary, and verify the behavior with tests.
- Evaluate security controls proportionately: added components and complexity can create attack surface, configuration mistakes, and maintenance burden, potentially increasing overall risk. Do not add complexity without a clear threat reduction, but do not omit necessary controls merely to keep the design small. Prefer the simplest effective control and assess its residual risk and operational cost.
- Ask the user to decide material security-design choices before implementing them when requirements leave multiple reasonable approaches or the choice changes trust boundaries, identity/credential handling, authorization policy, deployment, or operational burden. Explain the meaningful options and tradeoffs; do not silently choose a security architecture or infer consent from a general security goal.
- The C++ API and Flask dashboard have no authentication or authorization. Do not expose either service to the public internet; keep them on localhost or a trusted, isolated management network.
- Firewall rule changes are privileged, immediate, and are not automatically rolled back. Do not issue mutating API requests or run firewall-changing operations against a live host unless the user explicitly authorizes it and the environment is an appropriate test system.
- Keep API rule inputs structured; do not introduce raw nftables command execution from request data. See [SECURITY.md](SECURITY.md) before changing firewall or network-facing behavior.
