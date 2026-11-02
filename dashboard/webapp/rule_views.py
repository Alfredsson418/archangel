"""Routes for collecting, reviewing, and applying firewall changes."""
import json
import uuid

from flask import current_app, redirect, render_template, request, session, url_for

from . import pending_changes
from .api_client import API_SCHEMA_VERSION, ApiConnectionError, ApiResponseError
from .connection_check import (
    COULD_BLOCK,
    UNKNOWN_CONNECTION,
    WILL_BLOCK,
    browser_crosses_firewall,
    connection_from_status,
)
from .firewall_changes import (
    ADD_RULE,
    DELETE_RULE,
    affects_incoming_traffic,
    api_payload,
    apply_to_ruleset,
    chain_key,
    change_chain,
    change_warnings,
    chains_from,
    describe_change,
    find_rule,
    is_unmanaged,
    management_risk,
    stale_changes,
    verify_applied,
)
from .firewall_rules import (
    CONNECTION_STATES,
    MAX_RULE_BUNDLE_BYTES,
    MAX_RULE_BUNDLE_SIZE_TEXT,
    RULE_ACTIONS,
    RULE_FAMILIES,
    RULE_PROTOCOLS,
    describe_rule,
    portable_rule,
    ruleset_shape_error,
    validate_rule,
    validate_rule_bundle,
)
from .page_data import BackendSessionExpired, fetch, load
from .views import pages


_APPLY_FAILED_UNKNOWN = "The change may or may not have been applied. Check the rules before trying again."
_FORM_FIELDS = (
    "chain",
    "protocol",
    "source_address",
    "destination_address",
    "destination_port",
    "input_interface",
    "output_interface",
    "action",
)


def _actor_id():
    """Return the signed-in user's backend ID, which owns pending changes."""
    actor = session.get("actor_id")
    return actor if isinstance(actor, str) else None


@pages.app_context_processor
def _pending_change_context():
    """Expose how many changes are waiting, for the notice on every page.

    Returns:
        Template variables for the shared layout.
    """
    actor = _actor_id()
    if actor is None or request.endpoint in (None, "static", "pages.login"):
        return {"pending_change_count": 0}
    return {"pending_change_count": pending_changes.count(actor)}


def _store_changes(changes):
    """Add changes to the signed-in user's pending changes, all or none.

    Records each chain's revision the first time it's touched, so that applying
    later is refused if the chain has changed since then.

    Returns:
        An error message, or None on success.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    actor = _actor_id()
    pending = pending_changes.load(actor)
    if len(pending["changes"]) + len(changes) > pending_changes.MAX_PENDING_CHANGES:
        return f"You can have up to {pending_changes.MAX_PENDING_CHANGES} pending changes. Apply or remove some first."
    touched = {change_chain(change) for change in changes}
    new_chains = touched - set(pending["revisions"])
    if new_chains:
        revisions, error = load("/api/v1/firewall/revisions")
        if error:
            return "The backend is unavailable, so nothing was added."
        current = _revision_map(revisions)
        missing = new_chains - set(current)
        if missing:
            return f"These chains don't exist, so nothing was added: {', '.join(sorted(missing))}."
        pending["revisions"].update({chain: current[chain] for chain in new_chains})
    for change in changes:
        change["id"] = uuid.uuid4().hex
    pending["changes"].extend(changes)
    pending_changes.save(actor, pending)
    return None


def add_rules_to_pending(rules):
    """Add new rules to the signed-in user's pending changes, all or none.

    Returns:
        An error message, or None on success.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    return _store_changes([{"type": ADD_RULE, "rule": rule} for rule in rules])


def _revision_map(revisions):
    """Convert the API's revision list into a dictionary keyed by chain.

    Returns:
        A dictionary of chain keys to revisions.
    """
    chains = revisions.get("chains") if isinstance(revisions, dict) else None
    return {
        chain_key(chain["family"], chain["table"], chain["chain"]): chain["revision"]
        for chain in (chains if isinstance(chains, list) else [])
    }


def _rule_from_form(form):
    """Build a structured rule from submitted form fields.

    Returns:
        A pair of (rule dictionary, error message or None). The rule is
        normalized when there's no error.
    """
    parts = form.get("chain", "").split(" ")
    if len(parts) != 3 or parts[0] not in RULE_FAMILIES:
        return None, "Choose a chain."
    rule = {
        "family": parts[0],
        "table": parts[1],
        "chain": parts[2],
        "action": form.get("action", ""),
    }
    for field in ("protocol", "source_address", "destination_address", "input_interface", "output_interface"):
        value = form.get(field, "").strip()
        if value:
            rule[field] = value
    port_text = form.get("destination_port", "").strip()
    if port_text:
        start, separator, end = port_text.partition("-")
        if not start.strip().isdecimal() or (separator and not end.strip().isdecimal()):
            return None, "Destination port must be a port such as 443 or a range such as 8000-8100."
        rule["destination_port"] = int(start)
        if separator:
            rule["destination_port_end"] = int(end)
    states = form.getlist("connection_states")
    if states:
        rule["connection_states"] = states
    try:
        return validate_rule(rule, "This rule"), None
    except ValueError as error:
        return None, str(error)


def _values_from_rule(rule):
    """Fill the rule form's fields from a structured rule.

    Returns:
        A dictionary of form values.
    """
    port = rule.get("destination_port")
    end = rule.get("destination_port_end")
    return {
        "chain": chain_key(rule["family"], rule["table"], rule["chain"]),
        "action": rule["action"],
        "protocol": rule.get("protocol", ""),
        "source_address": rule.get("source_address", ""),
        "destination_address": rule.get("destination_address", ""),
        "destination_port": "" if port is None else (f"{port}-{end}" if end else str(port)),
        "input_interface": rule.get("input_interface", ""),
        "output_interface": rule.get("output_interface", ""),
        "connection_states": rule.get("connection_states", []),
    }


def _render_rule_form(*, chains, values, error=None, preview=None, message=None, status=200):
    """Render the rule form.

    Returns:
        A pair of (rendered HTML, HTTP status code).
    """
    return (
        render_template(
            "rule_form.html",
            chains=chains,
            values=values,
            error=error,
            preview=preview,
            message=message,
            protocols=RULE_PROTOCOLS,
            actions=RULE_ACTIONS,
            states=CONNECTION_STATES,
        ),
        status,
    )


def _form_chains():
    """Load the chains a rule can be added to.

    Returns:
        A pair of (chain list, error message or None).

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    ruleset, error = load("/api/v1/rules")
    if error is None:
        error = ruleset_shape_error(ruleset)
    return (chains_from(ruleset) if error is None else []), error


@pages.route("/rules/new", methods=["GET", "POST"])
def new_rule():
    """Show the rule form, preview a rule, or add it to pending changes.

    Returns:
        The rendered form with an HTTP status, or a redirect after adding.
    """
    chains, error = _form_chains()
    if request.method == "GET":
        return _render_rule_form(chains=chains, values=_duplicated_values() or {"action": "accept"}, error=error)

    values = {field: request.form.get(field, "") for field in _FORM_FIELDS}
    values["connection_states"] = request.form.getlist("connection_states")
    rule, form_error = _rule_from_form(request.form)
    if form_error:
        return _render_rule_form(chains=chains, values=values, error=form_error, status=400)
    action = request.form.get("form_action", "preview")
    if action == "preview":
        return _render_rule_form(chains=chains, values=values, preview=describe_rule(rule))

    store_error = add_rules_to_pending([rule])
    if store_error:
        return _render_rule_form(chains=chains, values=values, error=store_error, status=409)
    current_app.logger.info("firewall_change_added type=%s", ADD_RULE)
    if action == "add_another":
        # Keep the values, so that adding many similar rules is quick.
        return _render_rule_form(
            chains=chains,
            values=values,
            message=f"Added to pending changes: {describe_rule(rule)}. Change what differs for the next rule.",
        )
    return redirect(url_for("pages.review_changes"))


def _duplicated_values():
    """Fill the rule form from the existing rule named in the query string.

    Returns:
        A dictionary of form values, or None if no such rule can be represented.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    handle_text = request.args.get("handle", "")
    if not handle_text.isdecimal():
        return None
    ruleset, error = load("/api/v1/rules")
    if error is not None or ruleset_shape_error(ruleset):
        return None
    rule = find_rule(
        ruleset,
        request.args.get("family", ""),
        request.args.get("table", ""),
        request.args.get("chain", ""),
        int(handle_text),
    )
    portable = portable_rule(rule) if rule else None
    return _values_from_rule(portable) if portable else None


@pages.post("/rules/delete")
def delete_rule():
    """Add a rule's deletion to pending changes.

    Returns:
        A redirect to the review page, or the rules page with an error.
    """
    family = request.form.get("family", "")
    table = request.form.get("table", "")
    chain = request.form.get("chain", "")
    handle_text = request.form.get("handle", "")
    handle = int(handle_text) if handle_text.isdecimal() else None
    ruleset, error = load("/api/v1/rules")
    if error is None:
        error = ruleset_shape_error(ruleset)
    rule = find_rule(ruleset, family, table, chain, handle) if error is None else None
    if rule is None:
        return _rules_redirect(False, error or "This rule has changed or no longer exists, so nothing was added.")
    store_error = _store_changes(
        [{"type": DELETE_RULE, "family": family, "table": table, "chain": chain, "handle": handle, "before": rule}]
    )
    if store_error:
        return _rules_redirect(False, store_error)
    current_app.logger.info("firewall_change_added type=%s", DELETE_RULE)
    return redirect(url_for("pages.review_changes"))


@pages.route("/rules/import", methods=["GET", "POST"])
def import_rules():
    """Preview a portable rules bundle, or add its rules to pending changes.

    Returns:
        Rendered import page with an HTTP status, or a redirect after adding.
    """
    if request.method == "GET":
        return render_template("rules_import.html")

    if request.form.get("action") == "add":
        raw_bundle = request.form.get("bundle", "")
        if len(raw_bundle.encode("utf-8")) > MAX_RULE_BUNDLE_BYTES:
            return render_template("rules_import.html", error=f"The bundle exceeds the {MAX_RULE_BUNDLE_SIZE_TEXT} limit."), 413
        try:
            rules = validate_rule_bundle(json.loads(raw_bundle))
        except (json.JSONDecodeError, ValueError) as error:
            return render_template("rules_import.html", error=str(error)), 400
        if not rules:
            return render_template("rules_import.html", message="This bundle has no rules, so nothing was added.")
        store_error = add_rules_to_pending(rules)
        if store_error:
            return render_template("rules_import.html", error=store_error), 409
        current_app.logger.info("firewall_rule_bundle_added_to_pending count=%s", len(rules))
        return redirect(url_for("pages.review_changes"))

    raw_bundle = request.files.get("bundle_file")
    if raw_bundle is None:
        return render_template("rules_import.html", error="Choose a JSON bundle to preview."), 400
    content = raw_bundle.stream.read(MAX_RULE_BUNDLE_BYTES + 1)
    if len(content) > MAX_RULE_BUNDLE_BYTES:
        return render_template("rules_import.html", error=f"The bundle exceeds the {MAX_RULE_BUNDLE_SIZE_TEXT} limit."), 413
    try:
        bundle = json.loads(content.decode("utf-8"))
        rules = validate_rule_bundle(bundle)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return render_template("rules_import.html", error=f"Invalid firewall bundle: {error}"), 400
    return render_template(
        "rules_import.html",
        preview_rules=[dict(rule, description=describe_rule(rule)) for rule in rules],
        bundle_json=json.dumps(bundle, separators=(",", ":")),
        omitted_unsupported_rules=bundle.get("omitted_unsupported_rules", 0),
    )


def _rules_redirect(success, message):
    """Return to the rules page, which shows the result once.

    Returns:
        A redirect, so that refreshing can't repeat what was just done.
    """
    session["firewall_result"] = {"success": success, "message": message}
    return redirect(url_for("pages.rules_page"))


def _load_connection():
    """Read how the backend sees the dashboard's connection.

    Returns:
        A Connection, or None if it can't be determined.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    status, error = load("/status/info")
    return connection_from_status(status) if error is None else None


def _load_interfaces():
    """Read the backend host's network interfaces.

    Returns:
        A list of names, or None if they can't be determined.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    system, error = load("/api/v1/system")
    interfaces = system.get("network_interfaces") if error is None and isinstance(system, dict) else None
    return interfaces if isinstance(interfaces, list) else None


def _call_changes_api(path, payload):
    """Send a change list to the API.

    Returns:
        A pair of (ApiResponse, decoded JSON payload or an empty dictionary).

    Raises:
        ApiConnectionError: If no response was received.
        BackendSessionExpired: If the backend rejects the session.
        ApiResponseError: If the API uses an unsupported schema version.
    """
    response = current_app.config["API_CLIENT"].request(
        path,
        method="POST",
        body=json.dumps(payload).encode("utf-8"),
        bearer_token=session.get("access_token"),
    )
    if response.status == 401:
        session.clear()
        raise BackendSessionExpired
    if response.schema_version != API_SCHEMA_VERSION:
        raise ApiResponseError("The API returned an unsupported schema version.", status=response.status)
    try:
        decoded = json.loads(response.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        decoded = {}
    return response, decoded if isinstance(decoded, dict) else {}


def _rejection_message(response, payload):
    """Explain why the API refused a change list.

    Returns:
        A message that says nothing was changed.
    """
    if response.status == 403:
        return "Your account can't make this change. Nothing was changed."
    if response.status == 429:
        wait = f" Wait {response.retry_after} seconds, then try again." if response.retry_after else " Wait, then try again."
        return f"Too many firewall changes.{wait} Nothing was changed."
    if response.status == 409:
        return "The firewall has changed since you reviewed this, so nothing was changed."
    detail = payload.get("error")
    return f"{detail or f'The API returned HTTP {response.status}.'} Nothing was changed."


def _review_context(pending, *, error=None, rejected_index=None):
    """Work out everything the review page shows for a pending change list.

    Returns:
        A dictionary of template variables. "can_apply" is False while the
        ruleset is unavailable or a change is stale.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    changes = pending["changes"]
    context = {
        "entries": [],
        "risk_entries": [],
        "other_entries": [],
        "risk_count": 0,
        "unmanaged_count": 0,
        "connection_warning": None,
        "connection_causes": (),
        "same_host_notice": False,
        "conflict": False,
        "error": error,
        "can_apply": False,
    }
    if not changes:
        return context
    ruleset, load_error = load("/api/v1/rules")
    if load_error is None:
        load_error = ruleset_shape_error(ruleset)
    if load_error:
        context["error"] = error or "The backend is unavailable, so these changes can't be reviewed."
        context["entries"] = context["other_entries"] = [
            {"change": change, "summary": describe_change(change), "warnings": [], "problem": None, "flagged": False}
            for change in changes
        ]
        return context

    connection = _load_connection()
    interfaces = _load_interfaces()
    after = apply_to_ruleset(ruleset, changes)
    check, flagged = management_risk(ruleset, changes, connection)
    stale = stale_changes(ruleset, changes)

    revisions, revision_error = load("/api/v1/firewall/revisions")
    current = _revision_map(revisions) if revision_error is None else None
    conflicting = (
        {
            change["id"]
            for change in changes
            if current is not None
            and current.get(change_chain(change)) != pending["revisions"].get(change_chain(change))
        }
        if current is not None
        else set()
    )
    if rejected_index is None and not stale and not conflicting and current is not None:
        rejected_index, check_error = _check_changes(pending)
        if check_error and not context["error"]:
            context["error"] = check_error

    for index, change in enumerate(changes):
        problem = None
        if change["id"] in stale:
            problem = "This rule has changed or no longer exists. Remove this change."
        elif change["id"] in conflicting:
            problem = "This chain has changed since you added this. Review it against the current firewall."
        elif index == rejected_index:
            problem = "The firewall rejected this change."
        entry = {
            "change": change,
            "summary": describe_change(change),
            "warnings": change_warnings(ruleset, after, change, interfaces),
            "problem": problem,
            "flagged": change["id"] in flagged,
        }
        context["entries"].append(entry)
        (context["risk_entries"] if entry["flagged"] else context["other_entries"]).append(entry)

    context["risk_count"] = len(context["risk_entries"])
    context["unmanaged_count"] = sum(1 for change in changes if is_unmanaged(change))
    context["conflict"] = bool(conflicting)
    context["connection_causes"] = check.causes
    if check.status in (WILL_BLOCK, COULD_BLOCK, UNKNOWN_CONNECTION):
        context["connection_warning"] = check.status
    context["same_host_notice"] = browser_crosses_firewall(connection, request.remote_addr) and affects_incoming_traffic(
        ruleset, changes
    )
    context["can_apply"] = not stale and not conflicting and rejected_index is None and current is not None
    return context


def _check_changes(pending):
    """Ask the backend whether a change list would apply, without applying it.

    Returns:
        A pair of (index of a rejected change or None, error message or None).

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    try:
        response, payload = _call_changes_api("/api/v1/firewall/changes/check", api_payload(pending))
    except (ApiConnectionError, ApiResponseError):
        return None, "The backend couldn't check these changes."
    if 200 <= response.status < 300:
        return None, None
    index = payload.get("change_index")
    if response.status == 422 and isinstance(index, int) and not isinstance(index, bool):
        return index, None
    return None, _rejection_message(response, payload)


@pages.get("/changes")
def review_changes():
    """Show pending changes, before and after, with their warnings.

    Returns:
        Rendered review HTML.
    """
    pending = pending_changes.load(_actor_id())
    return render_template("changes.html", **_review_context(pending))


@pages.post("/changes/remove")
def remove_change():
    """Remove one pending change.

    Returns:
        A redirect to the review page.
    """
    actor = _actor_id()
    pending = pending_changes.load(actor)
    pending["changes"] = [change for change in pending["changes"] if change["id"] != request.form.get("id")]
    pending_changes.save(actor, pending)
    return redirect(url_for("pages.review_changes"))


@pages.post("/changes/discard")
def discard_changes():
    """Discard all pending changes.

    Returns:
        A redirect to the rules page.
    """
    pending_changes.save(_actor_id(), {"changes": [], "revisions": {}})
    current_app.logger.info("firewall_changes_discarded")
    return _rules_redirect(True, "Pending changes were discarded. Nothing was changed.")


@pages.post("/changes/refresh")
def refresh_changes():
    """Review pending changes against the firewall as it is now.

    Changes whose target has changed are still reported as stale.

    Returns:
        A redirect to the review page.
    """
    actor = _actor_id()
    pending = pending_changes.load(actor)
    revisions, error = load("/api/v1/firewall/revisions")
    if error is None:
        pending["revisions"].update(_revision_map(revisions))
        pending_changes.save(actor, pending)
    return redirect(url_for("pages.review_changes"))


@pages.post("/changes/apply")
def apply_changes():
    """Apply all pending changes in one transaction, after confirmation.

    The review is worked out again rather than trusted from the earlier page.

    Returns:
        A redirect after applying, or the review page with an HTTP status.
    """
    actor = _actor_id()
    pending = pending_changes.load(actor)
    if not pending["changes"]:
        return redirect(url_for("pages.review_changes"))
    context = _review_context(pending)

    def refuse(message, status):
        context["error"] = message
        return render_template("changes.html", **context), status

    if not context["can_apply"]:
        return refuse(context["error"] or "These changes can't be applied until the problems below are resolved. Nothing was changed.", 409)
    if request.form.get("confirm") != "yes":
        return refuse("Confirm that you reviewed the changes before applying them. Nothing was changed.", 400)
    if (context["risk_count"] or context["unmanaged_count"]) and request.form.get("confirm_risk") != "yes":
        return refuse("Confirm the management risks and rules Archangel doesn't manage. Nothing was changed.", 400)

    try:
        response, payload = _call_changes_api("/api/v1/firewall/changes", api_payload(pending))
    except ApiConnectionError:
        current_app.logger.warning("firewall_changes_outcome_unknown count=%s", len(pending["changes"]))
        return refuse(_APPLY_FAILED_UNKNOWN, 502)
    except ApiResponseError as error:
        current_app.logger.warning("firewall_changes_outcome_unknown count=%s", len(pending["changes"]))
        return refuse(f"{error} {_APPLY_FAILED_UNKNOWN}", 502)

    if not 200 <= response.status < 300:
        current_app.logger.warning("firewall_changes_rejected status=%s", response.status)
        index = payload.get("change_index")
        rejected = index if response.status == 422 and isinstance(index, int) and not isinstance(index, bool) else None
        message = _rejection_message(response, payload)
        if response.status >= 500:
            message = _APPLY_FAILED_UNKNOWN
        return (
            render_template("changes.html", **_review_context(pending, error=message, rejected_index=rejected)),
            response.status if response.status in (403, 409, 422, 429) else 502,
        )

    applied = pending["changes"]
    pending_changes.save(actor, {"changes": [], "revisions": {}})
    current_app.logger.info("firewall_changes_applied count=%s", len(applied))
    try:
        confirmed = verify_applied(fetch("/api/v1/rules"), applied)
    except (ApiConnectionError, ApiResponseError):
        confirmed = False
    if not confirmed:
        current_app.logger.warning("firewall_changes_unverified count=%s", len(applied))
        return _rules_redirect(False, "The backend reported success, but the result couldn't be confirmed. Check the rules below.")
    count = len(applied)
    return _rules_redirect(True, f"Applied {count} change{'' if count == 1 else 's'}. The firewall now shows the result below.")
