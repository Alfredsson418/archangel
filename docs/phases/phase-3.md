# Phase 3 Design: Safe Firewall Management in the Dashboard

**Status: Accepted. Nothing in this document is implemented.** The developer accepted this design on 2026-11-02, after expanding an earlier version to include rule editing, drag-and-drop ordering, editable tables and chains, the full set of rule features including NAT, and pending changes that are reviewed and applied together. See the [roadmap](../roadmap.md#phase-3-safe-firewall-management-in-the-dashboard) for requirements and exit criteria.

## Scope

Phase 3 lets an authorized user manage the firewall from the Firewall Configuration page. Changes are collected as [pending changes](#pending-changes), which have no effect until the user reviews and applies them together as one all-or-nothing transaction.

- Create, edit, and delete individual rules, with a [rule form](#what-the-rule-form-covers) that covers addresses, ports, connection state, interfaces, ICMP, logging, counters, rate limits, and NAT.
- Change the order of rules in a chain by dragging them.
- Create, rename, and delete chains, including NAT chains, and change a base chain's policy.
- Create and delete tables, and turn a table's enforcement on or off.
- Add many rules at once, by repeating the form or importing a bundle into pending changes.

Each change shows its exact target and effect, [warns if it could disturb the dashboard's connection](#connection-warning) to the API, requires confirmation, and reports what actually happened.

These are out of scope:

- **Renaming tables, and changing a base chain's hook or priority.** nftables can't change these in place. See [Backend restrictions](#backend-restrictions).
- **Moving rules between chains.** Ordering works within one chain in this phase. nftables supports moves between chains, so this could be added later.
- **Editing rules the structured form can't represent.** They can still be moved and deleted.
- **Named sets, maps, other nftables objects, and `route` chains.** These remain visible only through the ruleset and the CLI bundle. Rules that use them can be moved and deleted.
- **Rules that expire automatically.** Pending changes are drafts, not temporary firewall rules. Once applied, a rule stays until it's removed.
- **Shared drafts.** Pending changes belong to one user.
- **Automatic rollback.** This comes later, with the [mesh foundations](mesh.md#verification). Until then, the [connection warning](#connection-warning) is the main protection, and these features should be tested on systems with console access.
- **Fine-grained permissions.** This phase keeps the existing roles. See [Design choices](#design-choices).

## Starting point

These facts from the current code shape the design:

| Fact | Consequence |
| --- | --- |
| The API can only append and delete rules, and has no table or chain operations. | Unlike the earlier design, this phase has to extend the C++ API and the `Firewall::Backend` contract. |
| A failed delete returns a generic firewall error, and responses don't return the rule. | New operations need a specific conflict response, and the dashboard reads the ruleset again to prove each result. |
| The API's `/status/info` doesn't report the caller's address or the API's port as the backend sees them, while the dashboard knows only its own view. | The connection warning needs the API to report these. |
| The dashboard deliberately doesn't keep the user's role. | Controls are shown to everyone, and the dashboard handles `403`. |
| The Firewall Configuration page has no JavaScript and can sort rules by any column. | Dragging is the dashboard's first script, and it can't work on a sorted, multi-chain table. Ordering needs its own view of one chain, in true order. |
| The structured API requires a TCP or UDP protocol and accepts only single addresses and ports. | Common rules such as `ct state established,related accept` can't be created today, so the rule model has to grow. |
| The API ignores request fields it doesn't recognize. | A backend that doesn't understand a new field would silently create a broader rule than requested. See [Design choices](#design-choices). |
| **Every `reject` rule Archangel creates reads back as unsupported.** nftables reports the verdict with its default options, such as `{"type": "icmpx", "expr": "port-unreachable"}`, and `portable_rule` accepts only a bare `reject`. | Today these rules are left out of portable exports. They also couldn't be edited, so this is fixed first. |
| The bundle import has a preview and confirmation flow, and applies one API call per rule, so it can stop partway. `validate_rule_bundle` checks rule fields. | Importing can feed pending changes, which removes partial imports. Share that validation. |
| Browser sessions are JSON documents in the dashboard's SQLite store, and are cleared on sign-out or expiry. The backend's default idle limit is 15 minutes. | Pending changes kept in the session would be lost when it expires, so they get their own table. |
| CSRF, Origin checks, login enforcement, and fail-closed audit logging apply to dashboard requests, and the API applies roles and firewall-mutation limits per route. | New routes inherit these protections. |
| Only rules carry an ownership marker, the `archangel-managed` comment. Tables and chains have none. | A table or chain's ownership can't be known, so the design goes by the rules it contains. |

These nftables behaviors were tested in an isolated network namespace with nftables 1.1.6 on Linux 7.2. Later work should keep them covered, because the design depends on them:

| Tested behavior | Consequence |
| --- | --- |
| `replace rule` keeps the rule's handle and position. | Edits are atomic, and a failed edit can't lose the rule. |
| Deleting and re-inserting a rule in one transaction moves it, and a failure in any part leaves everything unchanged. | Reordering is atomic. |
| A moved rule gets a new handle. Its counters, comments, and references to named sets are preserved when copied from the JSON listing. | Any rule can be moved, including ones the form can't represent. The page must not rely on handles after a move. |
| Renaming a chain works, including base chains, and `jump` rules follow the new name. | Chain renames are safe. |
| There is no `rename table` command. | Renaming would mean recreating the table. |
| A base chain's policy can be changed, but its hook and priority can't. | Only the policy is editable. |
| **Deleting a non-empty chain succeeds and removes its rules without warning.** Deleting a chain that another rule jumps to fails. | Nothing in nftables protects against this, so the design has to. |
| A dormant table stops enforcing all of its rules. | Turning a table off needs the strongest warning. |
| A subnet with host bits, such as `192.168.1.5/24`, is accepted and silently stored as `192.168.1.0/24`. | The API has to reject these, or a rule could cover different addresses than the user typed. |
| In an `inet` table, a plain `reject` reads back as `icmpx`, but as `icmp` or `icmpv6` when the rule also matches an IPv4 or IPv6 address. | Reading a default `reject` has to take the rule's addresses into account. |
| A `/32` subnet reads back as a plain address, and the range `80-80` as a plain port. A reversed range is rejected. | Input is normalized, so that a rule matches what's read back. |
| Subnets read back as `prefix` objects and ranges as `range` objects. Connection state reads back as a string for one state and a list for several, using the `in` operator. A protocol match is left out when a port implies it. | The code that reads rules has to accept each of these shapes. |
| `iif` fails if the interface doesn't exist, while `iifname` and `oifname` accept any name. | The form uses names, so rules survive interfaces that appear later, such as VPN tunnels. A mistyped name is accepted, so the preview warns when the interface doesn't exist on the host. |
| nftables accepts rules that can never match: an input interface on an output hook, an output interface on an input hook, and ICMPv6 in the `ip` family. | nftables won't catch these, so validation and warnings have to. |
| Sets of ports or addresses, source ports, negated matches (`!=`), ICMP types, counters, log statements, and limits all read back as structured JSON. `limit` always reads back with its burst, defaulting to 5. | Each can be read and edited, and defaults are normalized. |
| Statement order matters, and nftables keeps it: a counter before a match counts packets the match would reject. | The form always writes matches, then limit, counter, and log, then the verdict. A rule in any other order can't be represented. |
| `replace rule` keeps a counter's values only if they're included in the replacement. | Editing a rule has to send its current counter values. |
| A log prefix accepts any characters, and an over-long one is rejected. | Prefixes are limited to a safe set of characters, since they appear in logs. |
| NAT statements only work in `nat` chains and only on certain hooks. In an `inet` table, `dnat` and `snat` need an explicit `ip` or `ip6`. A `drop` in a `nat` chain is accepted. | The form offers only the actions that fit the chosen chain, and always sets the family. |
| A single transaction can mix creating a chain, adding a rule that jumps to it, replacing and deleting rules, and adding more. A failure in the last step undid all of it. 1,000 added rules took well under a second. | Pending changes can be applied as one transaction. |
| Flushing a chain and re-adding its rules in one transaction gives any order, including new rules among existing ones, and keeps counters. All handles change. | Ordering can include pending new rules, which have no handles yet. |
| nftables can check a batch without applying it (`nft -c`, or `nft_ctx_set_dry_run` in libnftables). It caught stale handles, missing chains, wrong statement types, and missing interfaces. It didn't flag a `jump` loop, and a check doesn't guarantee that applying succeeds. | The review page can report most errors before the user confirms, but the apply step must still report failures. |
| On loopback, replies also pass the input hook, addressed to the client's temporary port, and NAT happens on the way out. | A same-host dashboard needs `established` allowed, which the connection check has to model. Allowing only the API's port locks it out. |
| After a table is deleted and recreated, its handles restart, so the same handle can identify a different rule. | A handle alone doesn't safely identify a rule. |

## Behavior

### What the rule form covers

| Field | Accepted | Example |
| --- | --- | --- |
| Chain | An existing chain in the `ip`, `ip6`, or `inet` family | `inet filter input` |
| Protocol | Any, TCP, UDP, ICMP, or ICMPv6. Ports require TCP or UDP. ICMP needs `ip` or `inet`, and ICMPv6 needs `ip6` or `inet`. | TCP |
| ICMP type | Optional, one or several, for ICMP or ICMPv6 | `echo-request` |
| Source and destination address | Optional, an address, subnet, or list of these, matching the family. Can be negated. | `192.168.1.0/24` |
| Source and destination port | Optional, a port, range, or list of these. Can be negated. | `22, 8000-8100` |
| Input and output interface | Optional, one interface name each | `lo` |
| Connection state | Optional, any of new, established, related, and invalid | established, related |
| Rate limit | Optional, a rate, period, burst, and whether it applies under or over the limit | 5 per minute |
| Counter | On or off | On |
| Log | Optional, with a short prefix | `ssh: ` |
| Action in a `filter` chain | Accept, drop, reject with optional reject options, or `jump` or `goto` a regular chain | Reject with TCP reset |
| Action in a `nat` chain | Destination NAT or redirect on prerouting and output hooks. Source NAT or masquerade on postrouting and input hooks, as nftables allows. | DNAT to `10.0.0.5:8080` |

At least one match is required, except for a counter or log rule, or NAT. Rules that use anything else can't be edited in the form, but can still be moved and deleted. That includes named sets and maps, `iif` and `oif`, and statements in a different order.

### Pending changes

Every change in the dashboard goes through the same steps, whether it's one rule or hundreds:

1. **Collect.** Each action below adds to the user's pending changes, and the firewall doesn't change. Every page shows a notice such as "3 pending changes: not applied yet", linking to the review page.
2. **Review.** The review page shows the [list of changes](#list-of-changes), before and after, with any that could disrupt management connections flagged. The user can remove individual changes or discard them all. The page shows the [warnings](#warnings) and [connection warning](#connection-warning) for the combined result, and asks the backend to check the whole batch without applying it, naming any change it rejects.
3. **Confirm.** The user ticks a confirmation box. If the list contains a management risk or anything that isn't Archangel's, a second box names how many, and deleting a table or non-empty chain, or turning a table off, also needs a typed name.
4. **Apply.** All changes apply in one transaction, so either all of them take effect or none do. The firewall never passes through an in-between state.
5. **Verify.** The dashboard reads the ruleset again, reports the result, and clears the pending changes.

If the ruleset has changed since the changes were reviewed, nothing is applied. The review page marks the affected changes and keeps them, so the user can adjust and retry. If the outcome is unknown, the changes are also kept, and the page explains this rather than retrying. The API's check of each chain's state refuses an accidental second apply.

### List of changes

The review page is the last thing the user sees before confirming. It opens with a summary, such as "12 changes: 2 MANAGEMENT RISK, 10 other", followed by the flagged changes in their own section and then all others. Each entry shows its target and its state before and after the change, in the form `before -> new`:

| Change | Target | Before -> new |
| --- | --- | --- |
| New rule | `inet filter input` | `(none) -> accept tcp dport 443 from 192.0.2.10` |
| Edited rule | `inet filter input`, handle 12 | `accept tcp dport 22 -> accept tcp dport 22 from 192.0.2.0/24` |
| Moved rule | `inet filter input`, handle 12 | `position 5 -> position 2` |
| Deleted rule | `inet filter input`, handle 12 | `drop tcp dport 23 -> (deleted)` |
| Renamed chain | `inet filter` | `helper -> blocklist` |
| **MANAGEMENT RISK** Chain policy | `inet filter input` | `accept -> drop` |
| Deleted chain | `inet filter blocklist` | `4 rules -> (deleted)` |
| **MANAGEMENT RISK** Deleted table | `inet filter` | `3 chains, 40 rules, 2 sets -> (deleted)` |
| Table enforcement | `inet filter` | `on -> off` |

Rules appear in plain language, with their full expression available, so that nothing is hidden. A moved chain's complete old and new order can also be opened from its entry, with new rules marked.

A change is flagged **MANAGEMENT RISK**, in text as well as color, only if it causes a "will block" or "could block" result in the [connection warning](#connection-warning), whatever kind of change it is. The flag means this change could disrupt the connections used to manage this firewall. A deletion or a move that doesn't affect them isn't flagged, so the flag stays meaningful however long the list is. The examples above assume the policy and table changes are the ones blocking the connection.

Other risks, such as deleting something large, are handled separately by the [warnings](#warnings) and typed-name confirmations.

### Creating and editing a rule

1. The user selects **Add rule**, or **Edit** on a rule. The form offers a chain from the active ruleset and the [fields above](#what-the-rule-form-covers). When editing, the chain is fixed and the form starts with the rule's current values.
2. Submitting shows the rule in plain language, for example: "Accept TCP traffic to port 443 from 192.0.2.10". An edit shows the old and new rule side by side. A new rule goes at the end of its chain, unless the user moves it, and earlier rules take priority.
3. The user adds it to pending changes. **Add and create another** returns to the form with the same chain and values, to make adding many similar rules quick. **Duplicate** on an existing rule starts from its values.

An edit keeps the rule's position, handle, and comment, so a managed rule stays managed and an unmanaged one stays unmanaged. A rule the form can't represent shows a disabled **Edit** control with the reason.

### Importing rules

Uploading a portable rule bundle validates and previews it as it does today. Accepting the preview adds its rules to pending changes, so an import now applies completely or not at all, and can be reviewed and combined with other changes.

### Deleting a rule

**Delete** adds the deletion to pending changes. The review page shows the rule's chain, handle, and full expression, and whether Archangel manages it. A rule Archangel doesn't manage also requires the second confirmation box, stating that another program or administrator may depend on it.

### Navigating the firewall

The Firewall Configuration page has a file tree on the left: families, then tables. Each list in the tree ends with an entry to add to it: **+ New table** in a family, and **+ New chain** in a table. **Expand all** and **Minimize all** open or close the tree's branches, and the tree remembers what's open in that browser. Selecting a table expands its chains in the tree and shows them on the right, each with its rules in true order. Selecting a chain narrows the right side to that chain, which the page states, with a link to show every chain. Tables and chains are managed where they're shown, so there's no separate page for them, and a chain's actions sit beside its rules. The selection is remembered for the session, so returning from a form or a review comes back to the same place, and a change's result is shown after applying it. Filtering narrows the tree to what matches. Sorting was removed, because within a chain only true order means anything.

### Ordering rules

Rule order decides what the firewall does, because the first matching verdict wins.

1. Each chain's rules have a drag handle, directly in the tree. If the chain has pending rule changes or a filter is active, the list isn't complete, so the chain links to its **Reorder rules** page instead, which includes pending new rules.
2. The user drags rows by their handles into a new order. **Move up** and **Move down** buttons do the same for keyboard and screen-reader users, and dragging works on touch screens. Without JavaScript, a form moves one rule to a chosen position.
3. Saving adds the new order to pending changes, and the review page shows the old and new order.

### Managing chains and tables

| Action | Confirmation shows | Extra safeguards |
| --- | --- | --- |
| Create a table or chain | The family, name, and for a base chain its type, hook, priority, and policy | A new base chain with a `drop` policy gets the connection check. |
| Rename a chain | Old and new name, and the number of rules that jump to it | Applied atomically. |
| Change a base chain's policy | Old and new policy, and the hook it affects | Changing to `drop` gets the connection check. |
| Delete a chain | Its rules, by number and content | Rejected while other rules jump to it, naming them. The user must type the chain's name if it has rules. |
| Delete a table | Its chains, rules, and other objects, by number | The user must always type the table's name. |
| Turn a table's enforcement off | Every chain and rule that stops being enforced | The user must type the table's name. The Firewall Configuration page shows a persistent notice while a table is off, and the overview reports it. |

If a table or chain being deleted contains rules Archangel doesn't manage, the page says so and requires the same second confirmation as deleting such a rule. It also warns that software such as Docker may recreate or depend on its own tables.

### Backend restrictions

These are deliberate deviations from "editable tables and chains". They come from the nftables backend, not from Archangel's own rules, and another firewall backend might not have them.

| Restriction | Cause | What the user sees |
| --- | --- | --- |
| Tables can't be renamed. | nftables has no rename command. Recreating a table would reset its handles and dynamic set contents, and could break software that expects its name. | The name is shown as fixed, with this explanation. To use a new name, create a new table and move to it. |
| A base chain's hook and priority can't be changed. | nftables rejects changes to them on an existing chain. | They are shown as fixed, with this explanation. To change them, create a new chain and move to it. |

Document these in [endpoints.md](../endpoints.md) when the table and chain routes are added, so that API users see them too.

### Connection warning

Rollback comes later, so the review page checks whether the pending changes together could disturb the connections that manage this firewall. Phase 3 checks one, and the [mesh](mesh.md#applying-a-change) adds its own later:

- **Dashboard to API:** TCP to the API's port, from the address the API sees for the dashboard.

The browser's connection to the dashboard isn't a management connection. The dashboard is intended to run on a separate management computer, where this firewall doesn't carry that connection. If they share a host, a rule that blocks the loopback interface still shows up through the check above.

One edge case gets its own notice. If the dashboard reaches the API over loopback and the browser's address isn't a loopback address, the user is reaching a dashboard on the firewall's own host from another computer. Whenever the pending changes affect incoming traffic, the review page says: "You're connected to this dashboard from another computer, through the firewall you're changing. These changes could disconnect you. This setup isn't recommended outside development or testing." This is a notice, not a MANAGEMENT RISK flag, because Archangel doesn't check whether the changes actually block the browser. A reverse proxy on the same host hides the browser's address, so the notice can't appear in that setup.

The dashboard works out the combined effect by following this connection through the current ruleset and the ruleset as it would be after every pending change. It checks both new and established traffic, in both directions, across every base chain on the relevant hooks in all tables, following `jump` and `goto`, and through NAT rules. Each "will block" or "could block" result names the change responsible, which is flagged in the [list of changes](#list-of-changes). Each result is one of these:

| Result | Message |
| --- | --- |
| Allowed now, blocked or redirected after | **Prominent warning:** "This change will block the dashboard's connection to the API. You may lose access, and may need console access to recover. Archangel can't undo this automatically." It names the rule or policy responsible. |
| Allowed now, can't be determined after | **Prominent warning:** "This change could block the dashboard's connection to the API." Causes include rate limits, interface matches, and named sets. |
| Can't determine the connection's details | **Warning:** "Archangel can't determine how the dashboard reaches the API, so it can't check this change." This happens if the API doesn't report its details, or if a proxy or NAT between them hides the real path. |
| No change detected | No connection warning. |

Like other warnings, it never blocks the change. Its absence doesn't prove the change is safe, because it only checks this connection and can't see other firewalls on the path, so the preview says so whenever the change affects an input or output hook. It doesn't check SSH or other access. It applies to every change: rules, order, chain policies, chain and table deletion, and turning a table off.

### Warnings

Warnings inform the user but never block the change once it's confirmed, because the dashboard can't fully predict a ruleset's effect. The API remains the only authority on what's allowed.

| Situation | Warning |
| --- | --- |
| New or edited `drop` or `reject` rule, or a `drop` policy, on an input hook | This could block other access to this server, such as SSH. The [connection warning](#connection-warning) covers the dashboard and API. |
| Deleting, editing, or moving an `accept` rule in a chain on an input hook | This could remove access that's currently allowed. |
| New order places a rule after a verdict with no conditions | The rule below it may never take effect. |
| A subnet covers every address (`/0`), or an `accept` rule has no address limit on an input hook | This applies to all addresses, which may be broader than intended. |
| An input interface on an output hook, or an output interface on an input hook | This rule can never match. |
| The named interface doesn't exist on this host | This may be a typing mistake, and the rule won't match until the interface exists. |
| A destination NAT to another host | This host must also forward the traffic, which Archangel doesn't configure. |
| A negated match with a broad action, such as `drop` for everything except one address | This also affects all other addresses. |
| A rule with logging and no rate limit on a busy hook | This could fill the logs quickly. |
| An identical rule already exists | This would add a duplicate. |
| Changing a rule, chain, or table that isn't Archangel's | Another program or administrator may depend on it. |

### Errors

Every outcome is stated in text, and the page never implies success if the API rejected or failed the change.

| Condition | Message |
| --- | --- |
| Invalid form input | Names the field and what's wrong, and keeps the user's values. Nothing is sent to the API. |
| API rejects the request (`400`) | Shows the API's safe error message. Nothing changed. |
| Viewer role or insufficient role (`403`) | "Your account can't make this change." |
| Session expired (`401`) | Returns to sign-in, using the existing handling. The change isn't resubmitted afterward. |
| Rate limited (`429`) | Asks the user to wait, using the API's `Retry-After` value. |
| Target changed or gone (`409`, `404`) | "This has changed since you reviewed it, so nothing was changed." Links to the current state. |
| Chain still referenced (`409`) | Names the rules that jump to it. |
| Backend unreachable before the request is sent | "The backend is unavailable. Nothing was changed." |
| No response after the request was sent, or the follow-up read fails | "The change may or may not have been applied. Check the rules before trying again." |

## Design choices

| Choice | Why | Rejected alternative |
| --- | --- | --- |
| **Include `jump`, `goto`, and `reject` options, but not named sets or maps** | Regular chains do nothing unless a rule can jump to them. Named sets and maps would need their own management pages. | Leaving regular chains unusable from the form. |
| **Grow the structured rule model to cover the full [rule form](#what-the-rule-form-covers)** | The developer wants these features usable from the dashboard, and without the basics the form can't express a default-deny policy. They stay structured data, so request values can never become nftables syntax. | Accepting raw nftables expressions, which project rules forbid. |
| **Match interfaces by name** | Names survive interfaces that come and go, and a default-deny policy normally needs a loopback rule. | `iif` and `oif`, which fail when the interface is absent. |
| **A fixed statement order: matches, limit, counter, log, verdict** | Gives each form setting one clear meaning. A rule in another order may mean something different, so it isn't rewritten. | Preserving any order in the form, which makes it impossible to show simply. |
| **Include NAT in this phase, restricted to actions that fit the chain** | The developer wants it usable from the dashboard. It's built last, because it needs `nat` chains and can redirect traffic. Operators manage it like other firewall settings. | A later separate design. |
| **The browser's connection to the dashboard isn't checked** | The dashboard's main use is on a separate computer, where this firewall doesn't carry that connection. Leaving it out also removes any need to guess the browser's address behind a reverse proxy. | Following the browser's connection through the ruleset when both share a host, which adds a lot of work for a setup that isn't recommended. A notice covers this case instead. |
| **A connection warning based on following a real connection through the ruleset** | Rollback comes later, so this is the main protection against lockouts. It names the responsible rule, and says when it can't tell. It's a warning, not a guarantee, and it lives in the dashboard as a pure function. | Warning on every `drop` rule, which people would learn to ignore. Blocking the change, which treats the dashboard as a security boundary. |
| **`/status/info` reports the caller's address and the API's port** | Only the backend sees these truly, especially across NAT or containers. It's already an authenticated route. | Guessing from the dashboard's own configuration. |
| **Reject subnets with host bits** | nftables would silently change the rule's meaning. Rejecting them with a suggested correction keeps what the user sees true. | Silently correcting them, which hides a possible typing mistake. |
| **The API rejects unknown rule fields, and the API schema version goes up** | A mismatched dashboard and backend then refuse the request, rather than dropping a field such as connection state and creating a broader rule. The services are independently deployable, so this can really happen. | Keeping the schema version, and relying on the read-back to catch a broader rule after it's already live. |
| **Treat each family's default `reject` as a plain `reject`** | Fixes the existing bug, so Archangel's own rules can be edited and exported. A `reject` with any other option, such as `tcp reset`, stays unrepresentable. | Adding reject options to the form, which isn't needed yet. |
| **Portable rule bundles move to version 2, and import accepts versions 1 and 2** | Version 2 can hold the new fields, and existing exported files keep working. | Adding fields to version 1, which older dashboards would reject with a confusing error. |
| **Edit with `replace rule`** | Atomic, and keeps the rule's position and handle. | Delete then add, which could lose the rule. |
| **Pending changes are stored on the dashboard, in their own table keyed by backend user ID, for 24 hours** | They survive an expired sign-in, which matters after adding many rules. The table lives in the dashboard's owner-only store, holds no credentials, and never authorizes anything: applying needs a valid session and passes through the API's authorization. Rule data does stay at rest for longer, and that store now holds more than [Phase 2](phase-2.md) described. | The browser session, which loses them on expiry. The backend, which would give the dashboard's drafts a place in the privileged service. |
| **Every change goes through pending changes** | One flow for one rule or hundreds, with one review page and one set of checks. A single change takes the same steps as before: fill in, review, confirm. | A separate "apply now" path alongside drafts, which doubles the flows to build and test. |
| **One atomic API operation, `POST /api/v1/firewall/changes`** | It takes an ordered list of structured changes and applies them in one transaction, with a check-only mode. This replaces the separate edit, order, chain, and table routes in the earlier design, so there's only one mutation path to secure, audit, and test. The existing rule routes stay for other API users. | A route per operation, whose calls can't be combined atomically. |
| **A change list is bounded and rate-limited as one firewall mutation** | Limits in `app_config.hpp` bound the number of changes. It counts as one request, so large batches aren't punished by the 30-per-minute limit, and they're still bounded. | Counting each change, which would make bulk changes impossible. |
| **Reordering rebuilds the chain within the transaction** | This is the only way to place new rules, which have no handles, among existing ones. The backend copies existing rules from its own listing, not from the request, so unrepresentable rules move safely and request data never becomes native rules. | Keeping handles stable, which nftables can't do for moved rules. |
| **Check before confirming, but still report apply failures** | The review page can catch most errors early. A check isn't a guarantee, as tested. | Trusting the check alone. |
| **Changes carry the revision of each chain they touch** | The backend reports a revision for each chain, computed from its rules and handles, excluding counters. A change list includes the revisions it was reviewed against, and the backend compares them under its lock immediately before applying. Handles alone are unsafe, as tested. This also refuses an accidental second apply. Changes made outside Archangel at that instant remain possible. | Comparing only in the dashboard, which leaves a window before the API call. Comparing the whole ruleset, which unrelated changes such as Docker's would keep invalidating. |
| **Dragging is a progressive enhancement** | The confirmation page and fallback form are server-rendered and work without JavaScript. The script only builds a form submission to Flask and never calls the C++ API, keeping the dashboard's server-side rule. | A browser client that calls the API, which project rules forbid. |
| **Drag directly in the tree, with a page for what the tree can't show** | The developer couldn't find dragging on a separate page. The tree shows each chain in true order, so handles can sit on the rules themselves. The page remains for chains with pending rule changes, and for the form that works without JavaScript. | A separate page only, which was hard to find. |
| **Create tables and chains from the last entry of their list in the tree** | The developer asked for this, so that creating one looks like appending to the list. A family with no tables still appears, so that it can get its first one. | A separate form elsewhere on the page. |
| **A file tree beside the selected table's chains, built with links** | The developer asked for a file tree on the left, where selecting a table opens its chains, because one long table is hard to navigate. Plain links need no JavaScript, work with a keyboard, and can be bookmarked. Chains start collapsed in a table with more than 30 rules. | A flat table. One long nested tree showing every chain at once, which the developer tried and found harder to read. |
| **Manage tables and chains in the tree, and remove sorting** | One place to find everything. Sorting across a chain's rules suggests an order the firewall doesn't use. | A separate tables and chains page, and sortable columns. |
| **Vendor SortableJS in `dashboard/static/`** | Handles touch and mouse dragging, and needs no build step. Isolated networks can't load it from a CDN. Keyboard buttons are added alongside it, since it doesn't provide them. | Hand-written dragging, which would be more code for touch support to maintain. The browser's native drag events, which don't work on touch screens. |
| **Typed-name confirmation for destructive structure changes** | nftables deletes non-empty chains without warning, and a tick box is too easy for losing a whole table. | A tick box, or refusing to delete non-empty chains, which would make the operator delete each rule first. |
| **Archangel manages its own table, and other tables are read-only** | The developer agreed this on 2026-11-02, replacing an earlier choice to manage every rule. Editing another program's table can break it, as described in [Next step](#next-step-table-ownership). | Managing every table with extra confirmation. Read-only only for `iptables-nft` tables, which wouldn't cover firewalld. |
| **Duplicate rules get a warning only** | Duplicates are harmless. | Blocking duplicates. |
| **A `before -> new` list with a MANAGEMENT RISK flag is the last step before confirming** | The user sees exactly what will change, with changes that could cut off management first. The flag comes from the connection check, not the kind of change, so it warns about what the developer cares about and isn't diluted by routine edits. Flags use text as well as color, as the [frontend guide](../frontend-design.md) requires. The second confirmation box covers both this and anything that isn't Archangel's, so a long list doesn't mean more boxes. | A "destructive" flag on every deletion or edit, which would be common enough to be ignored and would miss a harmless-looking rule that blocks access. Showing only the final ruleset, which makes the differences hard to see. |
| **The check works from a list of management connections** | Phase 3 has one: dashboard to API. The mesh adds its own to the same list, so the check and flag don't need a redesign. | A check written only for the dashboard and API. |
| **Dragging adds an order to pending changes** | Reordering usually means several moves, and confirming each would be tedious. The firewall also never passes through intermediate orders. | Confirming and applying each drop. |
| **Bundle import feeds pending changes** | Removes today's partial imports, one of the risks in [security concerns](../security-concerns.md). | Keeping one API call per imported rule. |
| **Ordering within one chain only** | Moving between chains can change which traffic a rule sees at all, and needs a more complex page. | Dragging between chains in the first version. |
| **No table renaming, recorded as a [backend restriction](#backend-restrictions)** | nftables can't do it, and recreating a table has side effects that a rename would hide. | Recreating a table in a transaction behind a "rename" button. |
| **A base chain's hook and priority stay read-only, recorded as a [backend restriction](#backend-restrictions)** | nftables can't change them in place. | Recreating the chain automatically. |
| **Operators manage the whole firewall, including tables, chains, and policies** | Operators manage the firewall and nodes. Administrators manage users and the underlying backend, such as restarts, and keep the firewall access they have today, so an administrator can fix a firewall problem without a second account. This phase needs no new role, and uses the API's existing per-route access checks, so finer permissions can be added later without changing this design. | Limiting tables, chains, and policies to administrators. Adding fine-grained permissions now. |
| **Build automatic rollback later, with a connection warning until then** | The developer chose to defer rollback. A lockout may need console access to fix until it exists, so test on systems that have it. | Building rollback first. |
| **Only `filter` and `nat` chains on `ip`, `ip6`, and `inet` can be created** | These are what the rule form supports. `route` chains and other families have different risks, and nothing in the form needs them. | Supporting every family and type. |
| **A separate review and confirmation step, validated again when applied** | Matches the import flow, and pending changes are checked again rather than trusted. | A JavaScript dialog, which is easy to dismiss and isn't server-side. |
| **Redirect after applying, and read the ruleset again** | Refreshing can't apply a change twice, and the page can prove the result. | Reporting success from the status code alone. |
| **Show controls to all roles and handle `403`** | Keeps authorization in the C++ API, and adds no identity data to Flask. | Storing the role in the session to hide controls. |
| **Warn but don't block** | The checks are simple pattern matches, and the dashboard isn't a security boundary. | Blocking risky changes. |

## Code changes

Each row is a separate piece of work, tested and committed on its own, in this order. Pieces 7 and 8 were committed together, because they share one page and one set of backend changes.

The check-only operation became its own route, `POST /api/v1/firewall/changes/check`, rather than a mode of `POST /api/v1/firewall/changes`, so that reviewing a list repeatedly doesn't use up the firewall-mutation rate limit. Chain revisions come from `GET /api/v1/firewall/revisions`, and `/api/v1/system` reports the host's interfaces for the missing-interface warning.

The work is grouped into four parts, each reported to the developer when finished: Part 1 is pieces 1 and 2, Part 2 is pieces 3 to 5, Part 3 is pieces 6 to 8, and Part 4 is pieces 9 to 12.

| Work | Backend | Dashboard |
| --- | --- | --- |
| **1. Core rule model** | `Firewall::RuleSpec` and `POST /api/v1/rules` gain subnets, port ranges, connection state, interfaces, ICMP, and optional protocol. Unknown fields are rejected, and the schema version goes up. | `portable_rule` and bundle validation handle the new fields and default `reject`. Bundle version 2. |
| **2. Connection warning** | `/status/info` reports the caller's address and API port. | Connection check as a pure function, with test fixtures. |
| **3. Pending changes: create and delete rules** | `POST /api/v1/firewall/changes` with check-only mode and chain revisions, starting with adding and deleting rules. | Pending-changes storage, notice, review page, warnings, and result checks. Rule form, with shared validation in `firewall_rules.py`. |
| **4. Bulk input** | None. | **Add and create another**, **Duplicate**, and bundle import into pending changes. |
| **5. Edit rules** | Replace-rule change, using `replace rule`. | Edit form and old-and-new view. |
| **6. Order rules** | Order change that rebuilds the chain in the transaction. | Organize page, vendored SortableJS, keyboard buttons, and no-JavaScript form. |
| **7. Chains** | Chain changes. | Chain forms and confirmations. |
| **8. Tables** | Table changes. | Table forms, confirmations, and the enforcement-off notice. |
| **9. Logging and counters** | Rule model additions. | Form fields, and links to the Logs page. |
| **10. Sets of values, source ports, negated matches, ICMP types, `jump`, `goto`, and `reject` options** | Rule model additions. | Form fields. |
| **11. Rate limits** | Rule model additions. | Form fields. |
| **12. NAT** | `nat` chains and NAT statements. | Form actions that depend on the chain, and NAT warnings. |

Across this work:

- `Firewall::Backend` gains these operations, with structured inputs only and domain errors for conflicts. The contract applies to every implementation, and the HTTP layer maps those errors to statuses.
- All new routes require the Operator or Administrator role, the same as today's firewall routes.
- Routes are registered in `backend/src/http/server.cpp`, handlers live in `backend/src/http/api/`, and all of these operations count as firewall mutations for rate limits and auditing.
- Limits, such as the maximum rules in an order request, go in `backend/include/config/app_config.hpp`.
- Logs record safe summaries such as `firewall_chain_deleted`, with no submitted values or rule contents.
- [security-concerns.md](../security-concerns.md) records that the dashboard's store now holds pending firewall changes for up to 24 hours.
- [endpoints.md](../endpoints.md), [security-concerns.md](../security-concerns.md), [frontend-design.md](../frontend-design.md), and the [roadmap](../roadmap.md) are updated as each piece lands.

## Next step: table ownership

The developer agreed this direction on 2026-11-02. **It isn't built yet, and it comes before Part 4**, because Part 4 adds rule types that can break another program's table. Until it's built, the dashboard can still change every table, as it does today.

### Why

Docker manages its `ip filter` table through `iptables`, and nftables labels such tables "do not touch". These were tested in a namespace with nftables 1.1.6:

| Tested behavior | Consequence |
| --- | --- |
| A rule with `ct state`, `log`, and `counter` added to a chain `iptables` owns makes `iptables` refuse that chain: "incompatible, use 'nft' tool". | Editing another program's table can break that program, possibly much later. |
| The same rule in a separate table leaves `iptables` working. | A separate table avoids the problem. |
| A table comment set at creation appears in the JSON listing, and survives turning enforcement off and on. | A table can carry an ownership marker, as rules do. |
| Adding a comment to an existing table reports success but does nothing. | Only tables Archangel creates can be marked. |
| The "managed by iptables-nft" warning appears only in the text listing, not in JSON. | Detecting that label would be fragile, so ownership relies on Archangel's own marker instead. |

### What to build

1. **Archangel's own table.** New rules go in a table Archangel creates, marked with the `archangel-managed` comment. Rules and chains in it are managed as they are today.
2. **Other tables are hidden and read-only.** A toggle on the Firewall Configuration page shows them. They can be viewed but not changed, and this covers `iptables-nft`, Docker, and firewalld tables alike. The C++ API enforces it, not only the dashboard.
3. **Hidden tables stay visible as a fact.** The page always states something like "3 other tables are hidden and still affect traffic" beside the toggle, because a hidden table can explain why a rule seems to do nothing.
4. **The connection check keeps looking at every table,** including hidden ones, so that its warnings stay accurate.
5. **The page explains how tables interact.** Every packet passes through all tables on a hook, and a drop in any of them is final. Archangel's rules can add restrictions, but an accept can't override another table's drop, and its drops can break another program's traffic. This was shown by the [connection check against real connections](../test.md#connection-check-against-real-connections).

### What this changes

- [Managing chains and tables](#managing-chains-and-tables), and the warnings and confirmations for rules Archangel doesn't manage, apply only to Archangel's own table once this is built. Their tests need updating with it.
- The API needs a way to refuse changes to tables without the marker, and every route that changes the firewall has to enforce it, including the older `POST` and `DELETE /api/v1/rules`. The CLI bundle import is a separate, explicit privileged operation.
- Part 4's rule types can then be used without risk to other tables. They're still useful for reading other tables' rules in plain language.

## Open decisions

| # | Decision | Recommendation | Why it matters |
| --- | --- | --- | --- |
| 1 | **Can a table Archangel didn't create be adopted?** An existing table can't be marked, including tables already created from the dashboard. | Decide when building the [next step](#next-step-table-ownership). Without adoption, those tables become read-only, and their rules would have to be recreated in Archangel's table. | Adoption would need its own record of ownership, since the table itself can't hold the marker. |
| 2 | **What is Archangel's table called, and in which family?** | `inet archangel`, so that one table handles IPv4 and IPv6. | The name becomes part of every deployment. |
| 3 | **Which chains does Archangel's table start with?** | Base chains on the `input`, `forward`, and `output` hooks with an `accept` policy, so that creating the table changes no traffic. | A `drop` policy here would apply on top of other tables, and could cut off access or Docker's networking. |

Earlier decisions were answered on 2026-11-02, and their answers are in [Design choices](#design-choices).

## Verification

C++ API tests use the existing mock firewall, and dashboard tests use the existing fake transport, so neither touches a real firewall. They cover:

- Success and rejection for every operation, including roles and rate limits.
- Rejected input, altered hidden fields, and missing confirmations, none of which reach the API.
- Each row of the [errors table](#errors), including the unknown-outcome case.
- Every form field reading back from each shape nftables reports, using fixtures taken from real output, including default `reject` in each family.
- Subnets with host bits, reversed ranges, mismatched families and ICMP, and unknown fields being rejected.
- A change list against an outdated chain revision, and a failure partway through a list, neither of which may change anything.
- Pending changes surviving review, removal of single items, discarding, a conflict, and a new sign-in, expiring after 24 hours, staying separate between users, and never applying without confirmation.
- A list at and just over its limits.
- The change list showing the correct before and after values for every kind of change, only changes behind a connection warning being flagged, the responsible change being the one flagged in a long list, and the second confirmation being required whenever a flag appears.
- Each warning appearing when it should, and not otherwise, including the same-host notice for a loopback API with a browser on another computer.
- The connection check against fixtures: rules, order, policies, deletion, and disabled tables that block, redirect, or don't affect the connection, and rules it can't evaluate.
- Typed-name confirmation, and the second confirmation for what isn't Archangel's.
- Pages rendering safely when rule, chain, or table names contain HTML.
- No rule contents or submitted values appearing in logs.

Because mocks can't prove nftables behavior, a separate integration check runs in an isolated network namespace, outside `make test`, and never against a live host's firewall. It covers each [tested behavior](#starting-point) above, and confirms that an edit, move, and failed transaction behave as designed.

The connection check is also compared with reality in a namespace: a real client connects through a ruleset, and the warning must agree with whether it could connect.

Dragging is checked manually in a browser with mouse and touch, along with keyboard use and use without JavaScript.
