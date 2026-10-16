# Project Goal and Direction

## Purpose

Archangel is an open-source firewall project intended to pair a privileged C++ firewall API with a dashboard and, over time, provide a clear and approachable management experience. The API is a backend service that other programs can call; see [endpoints.md](endpoints.md) for the current API and dashboard routes.

The current implementation is an early-stage personal project and is not yet a complete or production-ready firewall-management platform.

## Background and Long-Term Direction

This project continues ideas explored in the author's thesis, [Zero Trust i Komplexa Isolerade Miljöer](../assets/Zero_Trust_i_Komplexa_Isolerade_Miljöer.pdf), which is written in Swedish. Archangel relates most closely to the thesis's Edge Gateway concept. The broader vision is to help segment networks and control communication between resources through explicit policy.

See the [development roadmap](roadmap.md) for sequenced implementation work and completion criteria. The following diagrams represent conceptual direction, not a description of features that are all implemented today:

### Network zones and endpoints

Clients and servers would use a Resource Gateway (RG) or Device Agent (DA) to establish trusted communication with an Edge Gateway (EG). The RG is envisioned as providing access control for server resources; the DA is envisioned as providing client identity and credentials.

![Conceptual network zones](../assets/NZONE.png)

![Conceptual agent setup](../assets/AD.png)

### Segmentation and gateway communication

The long-term concept is to divide resources into network segments and allow only explicitly permitted communication. An Edge Gateway may protect a focused resource or service, while a Segmentation Gateway (SG) provides a logical boundary between Edge Gateways and routes authorized traffic between zones.

![Conceptual network plane](../assets/PD2.png)

![Conceptual network topology](../assets/NTOP.png)

![Conceptual Segmentation Gateway](../assets/SG.png)

The original vision also considers encrypted tunnels between Resource Gateways or Device Agents and Edge Gateways, and between Edge Gateways and the Segmentation Gateway. This could protect otherwise unencrypted traffic and reduce exposure on untrusted network links. The exact protocols, topology, threat model, and feasibility have not yet been decided.

### Administrative frontend and backend mesh

The intended role of the frontend is to be an administrative tool for configuring and updating backend services. The backend API is also intended to communicate with other backends so that multiple gateways or services can form a mesh, consistent with the wider gateway and segmentation concepts above. The frontend is a management surface, not the authority for backend identity, authentication, or authorization.

This is long-term direction, not current functionality. Peer identity and enrollment, authentication and authorization between backends, secure transport, discovery and membership, topology, configuration propagation, and failure handling all require explicit design. See the [development roadmap](roadmap.md) for sequencing and open decisions.

## Open Questions and Uncertainties

- The intended comparison with UniFi is about the desired quality of the management experience; exact feature parity, target users, and product scope are not defined.
- The gateway, Resource Gateway, Device Agent, and Segmentation Gateway architecture is a long-term concept. Only the functionality documented in the current source and [endpoints.md](endpoints.md) should be treated as implemented.
- User authentication and authorization, HTTPS, and rate limiting are planned, but their protocols and detailed designs have not been selected. The intended security model requires backend authentication and authorization on every API call; frontend login state alone must not authorize API access. See [SECURITY.md](../SECURITY.md) and the [development roadmap](roadmap.md).
- The intended administrative frontend and backend mesh have no finalized peer trust model, topology, protocols, or deployment design.
- Tunnel/VPN technology, key management, enrollment, routing behavior, and the deployment model remain open design decisions.
- Production readiness, supported platforms and firewall backends, operational requirements, and compatibility goals are not yet established.
