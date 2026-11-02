# Phase Designs

This folder records how each [roadmap](../roadmap.md) phase or major feature is built and why. The roadmap says what must be delivered and when it counts as complete. A design explains the choices made to get there, including the alternatives that were rejected.

| Work | Design | Status |
| --- | --- | --- |
| Phase 1: Testing and contribution readiness | [phase-1.md](phase-1.md) | Implemented; written after the fact |
| Phase 2: Backend-owned security controls | [phase-2.md](phase-2.md) | Implemented; written after the fact |
| Phase 3: Safe firewall management in the dashboard | [phase-3.md](phase-3.md) | Accepted |
| Mesh network | [mesh.md](mesh.md) | Accepted |

## Writing a design

Copy [TEMPLATE.md](TEMPLATE.md) to a new file named after the work, such as `phase-4.md`, keep every section, and add the design to the table above.

1. **Proposed:** write the design before implementing, including open decisions with recommendations.
2. **Accepted:** a developer has agreed every design choice, and no decisions remain open. Implementation starts here.
3. **Implemented:** the work is complete and the design matches what was built.

A design choice is anything that affects behavior, service boundaries, security, data formats, or operations. Bug fixes and work that follows an accepted design don't need a new document.

If a choice changes during implementation, update the design, state the reason, and get a developer's agreement again. Current behavior still belongs in the reference documents, such as [endpoints.md](../endpoints.md), which are updated as the work lands.
