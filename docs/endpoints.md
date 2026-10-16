# Exposed Endpoints
The C++ API runs separately from the Flask dashboard. Flask reads it directly while rendering pages and does not expose API passthrough routes.

## Flask Dashboard

### `GET /`

Renders the overview with rules, firewall statistics, and host statistics loaded server-side from the C++ API.

### `GET /rules`

Fetches the C++ ruleset in Flask and renders the firewall rules table with the `rules.html` template.

### `GET, POST /config`

Renders and updates the dashboard's C++ API connection setting.

## C++ API

### `GET /`

Returns a plain-text service status message.

### `GET /api/v1/rules`

Returns the nftables ruleset as JSON. The caller must have permission to query nftables.

### `GET /api/v1/stats`

Returns statistics computed by the selected firewall backend from its active ruleset:

```json
{
	"total_rules": 8,
	"total_tables": 2,
	"total_chains": 4,
	"rules_by_family": {"inet": 8},
	"rules_by_protocol": {"tcp": 5, "udp": 3},
	"rules_by_verdict": {"accept": 5, "drop": 2, "other": 1}
}
```

### `GET /api/v1/system`

Returns the gateway hostname, online CPU core count, 1/5/15-minute load averages, memory totals/usage, root filesystem totals/usage, and uptime. Usage values are in bytes with percentages for memory and disk.

### `POST /api/v1/rules`

Adds one rule to an existing family/table/chain. The request is JSON; raw nftables commands are not accepted.

```json
{
	"family": "inet",
	"table": "filter",
	"chain": "input",
	"protocol": "tcp",
	"source_address": "192.0.2.10",
	"destination_port": 443,
	"action": "accept"
}
```

`source_address`, `destination_address`, and `destination_port` are optional, but at least one match is required. Supported families are `ip`, `ip6`, and `inet`; protocols are `tcp` and `udp`; verdicts are `accept`, `drop`, and `reject`. Success returns HTTP `201`.

### `DELETE /api/v1/rules`

Deletes a rule by its family, table, chain, and numeric handle:

```json
{
	"family": "inet",
	"table": "filter",
	"chain": "input",
	"handle": 12
}
```

Mutating endpoints have no authentication and apply changes immediately. See [Security](../SECURITY.md) before enabling access beyond localhost.

When authentication is implemented, it is intended to be enforced by the C++ API on every API request, including reads and health/status requests, with authorization checked for each call. A dashboard login screen alone will not grant API access; requests must carry credentials or a verifiable backend-issued credential. This is planned behavior, not a current API capability.
