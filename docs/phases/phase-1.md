# Phase 1 Design: Testing and Contribution Readiness

**Status: Implemented.** See the [roadmap](../roadmap.md#phase-1-testing-and-contribution-readiness) for requirements and exit criteria.

> **Note:** This document was created on 2026-11-02, after Phase 1 was implemented, when design records moved to this folder. It wasn't written or agreed through the current design process. It records what the roadmap and code show, so reasons and rejected alternatives appear only where they were recorded at the time.

## Scope

Phase 1 adds automated tests, a repeatable verification workflow, contribution guidance, and a separation between Archangel-managed firewall rules and other rules in the backend's export and import. It doesn't add tests that need a privileged host or a live firewall.

## Starting point

Not recorded when this phase was designed. The roadmap describes the phase's work as adding these capabilities, without recording the earlier state in detail.

## Behavior

- `make test` runs the backend suite and returns a failing status for a failing test.
- GitHub Actions runs dashboard tests, backend unit tests, the C++ debug build, and a clang-format check on every push and pull request.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) describe how to contribute and how to report problems.
- Firewall bundle `replace` updates only marked rules, while `replace-all` explicitly flushes the full ruleset.

## Design choices

| Choice | Why | Rejected alternative |
| --- | --- | --- |
| **Tests use controlled fixtures and a mock firewall** | Tests stay isolated from privileged host state, and destructive operations must never run in ordinary test suites. | Tests against a live firewall. |
| **Ownership is marked with a reserved `archangel-managed` nftables comment** | Rules created through the structured API can be told apart from others, so that imports can replace only their own rules. | Not recorded. |
| **Firewall bundle v1 contains rules only, and is the only supported format** | Keeps firewall data separate from listener settings. | Not recorded. |
| **Replacing the full ruleset is a separate, explicit mode** | Flushing everything is destructive, so it must be requested by name. | Not recorded. |
| **Issue-first contribution process** | Recorded in [CONTRIBUTING.md](../../CONTRIBUTING.md). The reason wasn't recorded. | Not recorded. |

## Code changes

| Area | Change |
| --- | --- |
| `backend/tests/` | Tests for nftables statistics parsing, firewall bundle parsing and serialization, managed-rule replacement planning, and API handlers. |
| `backend/src/firewall/` | Firewall bundle v1 and managed-rule classification. |
| CI and [test.md](../test.md) | Automated checks and documented prerequisites, commands, and expected output. |
| [CONTRIBUTING.md](../../CONTRIBUTING.md), [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) | Contribution and conduct guidance. |

## Open decisions

None.

## Verification

See the phase's exit criteria in the [roadmap](../roadmap.md#phase-1-testing-and-contribution-readiness), and the commands in [test.md](../test.md). Tests for bundle export didn't exercise the real export path, which allowed a bug that made `--export-firewall-config` fail on every run. That was fixed on 2026-11-02.
