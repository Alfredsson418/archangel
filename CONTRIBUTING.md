# Contributing

Archangel is an early-stage firewall project. Discuss significant changes before implementing them so the scope, API contract, operational impact, and security implications can be reviewed.

## Before you start

- For a new feature or architectural change, open a GitHub issue describing the problem, proposed behavior, and relevant deployment context. Wait for agreement on scope before starting substantial implementation.
- For a bug, search existing issues first; include expected and actual behavior, the affected version or commit, and concise reproduction steps.
- For security vulnerabilities, do not open a public issue. Follow the private reporting instructions in [SECURITY.md](SECURITY.md).
- Avoid submitting unrelated changes together. Keep pull requests focused and explain user-visible or API behavior changes.

## Development setup and checks

Read the [testing and verification guide](docs/test.md) for prerequisites, test coverage, commands, and expected output. At minimum, run the checks relevant to your changes:

```sh
make test
make debug
(cd app/web && .venv/bin/python -m unittest)
```

The backend tests use mocks and controlled fixtures; they must not alter a live firewall. Do not run firewall-changing operations against a live host as part of testing.

## Implementation expectations

- Follow the repository's [agent and project guidelines](AGENTS.md), including source layout, formatting, security, and logging conventions.
- Keep HTTP parsing and validation in the API layer, firewall operations behind the `Firewall` abstraction, and response serialization at the API boundary.
- Use the existing versioned JSON API contract. Do not add raw nftables command execution from request data or introduce a second transport without prior design discussion.
- Keep deployment-specific addresses configurable. Do not assume the dashboard and managed backend share a host.
- Treat backend changes as privileged operations. Describe their impact, failure behavior, and recovery implications; do not imply changes roll back unless that behavior exists.
- Keep logs useful but free of request/response bodies, query values, form contents, credentials, secrets, and raw firewall-rule input.
- Add focused tests for behavior changes, including invalid input and failure cases. Tests should use mocks or fixtures rather than host firewall state.
- Use `.clang-format` for C++ and four-space indentation for Python. Keep functions and modules focused and avoid abstractions that do not clarify a real boundary.

## Documentation and pull requests

Keep documentation synchronized with behavior:

- Update [docs/endpoints.md](docs/endpoints.md) when routes, payloads, status codes, or API behavior change.
- Update [docs/endpoints.md](docs/endpoints.md) when backend CLI config schemas or import/export semantics change.
- Update [README.md](README.md) for project overview or build/run changes.
- Update [docs/test.md](docs/test.md) when tests, prerequisites, commands, or expected output change.
- Update [docs/security-concerns.md](docs/security-concerns.md) when current security limitations or planned controls change.
- Update [docs/roadmap.md](docs/roadmap.md) when scope, sequencing, status, or exit criteria change.

Pull requests should explain the problem and solution, list observable behavior changes, link the discussion issue where applicable, and report the checks run and their outcomes. Call out tests that could not be run and why. Include screenshots for material dashboard changes when useful, but do not include sensitive data.

## Conduct

Participation is subject to the [Code of Conduct](CODE_OF_CONDUCT.md). Report conduct concerns privately to the repository maintainers; do not post personal details or sensitive information in a public issue.
