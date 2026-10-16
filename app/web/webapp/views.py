import ipaddress
import json
import re
import secrets
from datetime import datetime
from pathlib import Path

from flask import Blueprint, current_app, make_response, render_template, request, session

from .api_client import (
    API_SCHEMA_VERSION,
    ApiConnectionError,
    ApiResponseError,
    check_api_health,
    fetch_json,
    request_backend,
    test_api_connection,
)
from .settings import save_api_url, valid_api_url


pages = Blueprint("pages", __name__)
RULE_BUNDLE_FORMAT = "archangel-firewall-rules"
RULE_BUNDLE_VERSION = 1
MAX_RULE_BUNDLE_BYTES = 512 * 1024
MAX_IMPORTED_RULES = 1000
SORTABLE_RULE_FIELDS = ("family", "table", "chain", "handle", "expr")
RULE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


def _load(path):
    """Load one API JSON resource for a rendered page.

    Returns:
        A pair of (decoded payload, None) on success, or (None, error text) if
        the backend request fails.
    """
    try:
        return fetch_json(current_app.config["API_URL"], path), None
    except (ApiConnectionError, ApiResponseError) as error:
        return None, str(error)


def _rules_from(ruleset):
    """Extract rule objects from an nftables ruleset response.

    Returns:
        A list of rule dictionaries, or an empty list for an invalid shape.
    """
    if not isinstance(ruleset, dict):
        return []
    entries = ruleset.get("nftables", [])
    if not isinstance(entries, list):
        return []
    return [entry["rule"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("rule"), dict)]


def _ruleset_shape_error(ruleset):
    """Return an error when the backend payload is not a complete ruleset."""
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        return "The backend returned an invalid firewall ruleset response."
    return None


def _portable_rule(rule):
    """Convert an nftables rule to the portable rule subset Archangel supports.

    Returns:
        A JSON-compatible rule specification, or None if the rule contains
        expressions outside the supported structured-rule contract.
    """
    if not isinstance(rule, dict):
        return None
    result = {}
    for field in ("family", "table", "chain"):
        value = rule.get(field)
        if not isinstance(value, str) or not value:
            return None
        result[field] = value

    expression = rule.get("expr")
    if not isinstance(expression, list):
        return None
    protocol = None
    action = None
    matches = {}
    for statement in expression:
        if not isinstance(statement, dict) or len(statement) != 1:
            return None
        if any(verdict in statement for verdict in ("accept", "drop", "reject")):
            verdict = next(verdict for verdict in ("accept", "drop", "reject") if verdict in statement)
            if action is not None or statement[verdict] is not None:
                return None
            action = verdict
            continue
        match = statement.get("match")
        if not isinstance(match, dict) or match.get("op") != "==":
            return None
        left = match.get("left")
        right = match.get("right")
        if not isinstance(left, dict) or len(left) != 1:
            return None
        if "meta" in left:
            meta = left["meta"]
            if (
                not isinstance(meta, dict)
                or meta.get("key") != "l4proto"
                or right not in ("tcp", "udp")
                or protocol is not None
            ):
                return None
            protocol = right
            continue
        payload = left.get("payload")
        if not isinstance(payload, dict):
            return None
        payload_protocol = payload.get("protocol")
        field = payload.get("field")
        if field in ("saddr", "daddr") and payload_protocol in ("ip", "ip6") and isinstance(right, str):
            target = "source_address" if field == "saddr" else "destination_address"
            if target in matches:
                return None
            try:
                address = ipaddress.ip_address(right)
            except ValueError:
                return None
            if (payload_protocol == "ip") != (address.version == 4):
                return None
            matches[target] = right
            continue
        if field == "dport" and payload_protocol in ("tcp", "udp") and isinstance(right, int) and not isinstance(right, bool):
            if "destination_port" in matches:
                return None
            matches["destination_port"] = right
            matches["port_protocol"] = payload_protocol
            continue
        return None

    if protocol not in ("tcp", "udp") or action not in ("accept", "drop", "reject"):
        return None
    if matches.get("port_protocol", protocol) != protocol:
        return None
    matches.pop("port_protocol", None)
    if not matches:
        return None
    result.update(protocol=protocol, action=action, **matches)
    return result


def _portable_bundle(ruleset):
    """Create a versioned portable configuration from supported live rules.

    Returns:
        A bundle and the number of active rules that were not representable.
    """
    rules = []
    skipped = 0
    for rule in _rules_from(ruleset):
        portable = _portable_rule(rule)
        if portable is None:
            skipped += 1
        else:
            rules.append(portable)
    return {
        "format": RULE_BUNDLE_FORMAT,
        "version": RULE_BUNDLE_VERSION,
        "rules": rules,
        "omitted_unsupported_rules": skipped,
    }, skipped


def _validate_rule_bundle(bundle):
    """Validate a portable rule bundle before showing or applying it.

    Returns:
        A list of normalized rule specifications.

    Raises:
        ValueError: If the bundle or any rule is invalid or unsupported.
    """
    if (
        not isinstance(bundle, dict)
        or bundle.get("format") != RULE_BUNDLE_FORMAT
        or bundle.get("version") != RULE_BUNDLE_VERSION
        or isinstance(bundle.get("version"), bool)
        or set(bundle) - {"format", "version", "rules", "omitted_unsupported_rules"}
    ):
        raise ValueError("The file is not a supported Archangel firewall-rules bundle.")
    omitted = bundle.get("omitted_unsupported_rules", 0)
    if not isinstance(omitted, int) or isinstance(omitted, bool) or omitted < 0:
        raise ValueError("The bundle has invalid unsupported-rule metadata.")
    rules = bundle.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_IMPORTED_RULES:
        raise ValueError(f"The bundle must contain no more than {MAX_IMPORTED_RULES} rules.")
    normalized = []
    allowed = {
        "family",
        "table",
        "chain",
        "protocol",
        "source_address",
        "destination_address",
        "destination_port",
        "action",
    }
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict) or set(rule) - allowed:
            raise ValueError(f"Rule {index} contains unsupported fields.")
        for field in ("family", "table", "chain", "protocol", "action"):
            if not isinstance(rule.get(field), str) or not rule[field]:
                raise ValueError(f"Rule {index} requires a non-empty {field}.")
        if rule["family"] not in ("ip", "ip6", "inet"):
            raise ValueError(f"Rule {index} has an unsupported address family.")
        if not RULE_NAME_PATTERN.fullmatch(rule["table"]) or not RULE_NAME_PATTERN.fullmatch(rule["chain"]):
            raise ValueError(f"Rule {index} has an invalid table or chain identifier.")
        if rule["protocol"] not in ("tcp", "udp") or rule["action"] not in ("accept", "drop", "reject"):
            raise ValueError(f"Rule {index} has an unsupported protocol or action.")
        has_match = False
        for field in ("source_address", "destination_address"):
            value = rule.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"Rule {index} has an invalid {field}.")
                try:
                    address = ipaddress.ip_address(value)
                except ValueError as error:
                    raise ValueError(f"Rule {index} has an invalid {field}.") from error
                if rule["family"] == "ip" and address.version != 4:
                    raise ValueError(f"Rule {index} has an address incompatible with its family.")
                if rule["family"] == "ip6" and address.version != 6:
                    raise ValueError(f"Rule {index} has an address incompatible with its family.")
                has_match = True
        if "destination_port" in rule:
            port = rule["destination_port"]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError(f"Rule {index} has an invalid destination port.")
            has_match = True
        if not has_match:
            raise ValueError(f"Rule {index} must have at least one address or destination-port match.")
        normalized.append({key: value for key, value in rule.items() if value is not None})
    return normalized


def _display_bytes(value):
    """Format a byte count for human-readable dashboard display.

    Returns:
        A scaled byte string, or "Unavailable" when value is None.
    """
    if value is None:
        return "Unavailable"
    value = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    return f"{value:.0f} {units[unit]}" if unit == 0 else f"{value:.1f} {units[unit]}"


def _firewall_status(ruleset):
    """Summarize whether nftables has base chains attached to packet hooks.

    Returns:
        A pair of (status label, active base-chain count).
    """
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        return "Unavailable", None
    active_chains = sum(
        1
        for entry in ruleset["nftables"]
        if isinstance(entry, dict)
        and isinstance(entry.get("chain"), dict)
        and isinstance(entry["chain"].get("hook"), str)
        and entry["chain"]["hook"]
    )
    return ("Active" if active_chains else "No active base chains"), active_chains


def _format_uptime(value):
    """Format a non-negative uptime in seconds as a compact duration.

    Returns:
        A human-readable duration, or "Unavailable" for invalid input.
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return "Unavailable"
    seconds = int(value)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _dashboard_context():
    """Build the overview from backend, firewall, and host-health data.

    Returns:
        A dictionary of values consumed by the overview template.
    """
    ruleset, rules_error = _load("/api/v1/rules")
    system, system_error = _load("/api/v1/system")
    backend, backend_error = _load("/status/info")
    try:
        check_api_health(current_app.config["API_URL"])
    except (ApiConnectionError, ApiResponseError) as error:
        health_error = str(error)
    else:
        health_error = None
    errors = [
        error
        for error in (health_error, rules_error, system_error, backend_error)
        if error
    ]
    system = system or {}
    backend = backend or {}
    loads = system.get("load_average") or []
    cpu_load = " / ".join("—" if value is None else f"{float(value):.2f}" for value in loads[:3]) or "Unavailable"
    firewall_status, active_base_chains = _firewall_status(ruleset)
    if health_error or rules_error:
        firewall_status = "Unavailable"
    return {
        "firewall_status": firewall_status,
        "active_base_chains": active_base_chains,
        "system": system,
        "backend": backend,
        "errors": errors,
        "api_connected": health_error is None,
        "last_updated": datetime.now().strftime("%H:%M:%S"),
        "cpu_load": cpu_load,
        "host_uptime": _format_uptime(system.get("uptime_seconds")),
        "memory_percent": system.get("memory_usage_percent"),
        "memory_detail": f"{_display_bytes(system.get('memory_used_bytes'))} used of {_display_bytes(system.get('memory_total_bytes'))}",
        "disk_percent": system.get("disk_usage_percent"),
        "disk_detail": f"{_display_bytes(system.get('disk_used_bytes'))} used of {_display_bytes(system.get('disk_total_bytes'))}",
    }


def _system_context():
    """Build read-only host and Archangel process management information.

    Returns:
        A dictionary of diagnostic data consumed by the system page.
    """
    system, system_error = _load("/api/v1/system")
    backend, backend_error = _load("/status/info")
    try:
        check_api_health(current_app.config["API_URL"])
    except (ApiConnectionError, ApiResponseError) as error:
        health_error = str(error)
    else:
        health_error = None
    system = system or {}
    backend = backend or {}
    loads = system.get("load_average") or []
    cpu_load = " / ".join("—" if value is None else f"{float(value):.2f}" for value in loads[:3]) or "Unavailable"
    errors = [error for error in (health_error, system_error, backend_error) if error]
    return {
        "system": system,
        "backend": backend,
        "errors": errors,
        "api_connected": health_error is None,
        "cpu_load": cpu_load,
        "host_uptime": _format_uptime(system.get("uptime_seconds")),
        "backend_uptime": _format_uptime(backend.get("uptime_seconds")),
        "memory_percent": system.get("memory_usage_percent"),
        "memory_detail": f"{_display_bytes(system.get('memory_used_bytes'))} used of {_display_bytes(system.get('memory_total_bytes'))}",
        "disk_percent": system.get("disk_usage_percent"),
        "disk_detail": f"{_display_bytes(system.get('disk_used_bytes'))} used of {_display_bytes(system.get('disk_total_bytes'))}",
    }


@pages.get("/")
def index():
    """Render the overview page with current backend data.

    Returns:
        Rendered overview HTML, converted to an HTTP response by Flask.
    """
    return render_template("index.html", **_dashboard_context())


@pages.get("/rules")
def rules_page():
    """Render the searchable, sortable active firewall rules page.

    Returns:
        Rendered rules HTML with normalized sort and filter state.
    """
    ruleset, error = _load("/api/v1/rules")
    if error is None:
        error = _ruleset_shape_error(ruleset)
    rules = _rules_from(ruleset) if error is None else []
    total_rules = len(rules)
    query = request.args.get("q", "").strip()[:100]
    sort = request.args.get("sort", "family")
    if sort not in SORTABLE_RULE_FIELDS:
        sort = "family"
    direction = request.args.get("direction", "asc")
    if direction not in ("asc", "desc"):
        direction = "asc"
    if query:
        needle = query.casefold()
        rules = [
            rule for rule in rules
            if needle in " ".join(
                str(rule.get(field, ""))
                for field in ("family", "table", "chain", "handle")
            ).casefold()
            or needle in json.dumps(rule.get("expr", []), sort_keys=True).casefold()
        ]
    def sort_key(rule):
        value = rule.get(sort, "")
        if sort == "handle" and isinstance(value, int) and not isinstance(value, bool):
            return (0, value)
        return (1, str(value).casefold())

    rules.sort(key=sort_key, reverse=direction == "desc")
    return render_template(
        "rules.html",
        rules=rules,
        total_rules=total_rules,
        error=error,
        query=query,
        sort=sort,
        direction=direction,
        sort_fields=SORTABLE_RULE_FIELDS,
    )


@pages.get("/rules/export")
def export_rules():
    """Download active Archangel-supported firewall rules as a portable bundle.

    Returns:
        A JSON attachment and a warning header if unsupported rules were omitted.
    """
    ruleset, error = _load("/api/v1/rules")
    if error:
        return render_template("rules.html", rules=[], error=error), 502
    shape_error = _ruleset_shape_error(ruleset)
    if shape_error:
        return render_template("rules.html", rules=[], error=shape_error), 502
    bundle, skipped = _portable_bundle(ruleset)
    response = make_response(json.dumps(bundle, indent=2) + "\n")
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = 'attachment; filename="archangel-firewall-rules.json"'
    if skipped:
        response.headers["X-Archangel-Skipped-Rules"] = str(skipped)
    current_app.logger.info(
        "firewall_rule_bundle_exported included=%s skipped=%s",
        len(bundle["rules"]),
        skipped,
    )
    return response


@pages.route("/rules/import", methods=["GET", "POST"])
def import_rules():
    """Preview or apply a validated, additive portable firewall-rules bundle.

    Returns:
        Rendered import/preview page with an appropriate HTTP status.
    """
    if request.method == "GET":
        return render_template("rules_import.html")

    if request.form.get("action") == "apply":
        csrf_token = session.get("rules_import_csrf")
        if (
            not isinstance(csrf_token, str)
            or not secrets.compare_digest(csrf_token, request.form.get("csrf_token", ""))
        ):
            return render_template(
                "rules_import.html",
                error="The import confirmation expired or is invalid. Preview the bundle again.",
            ), 400
        if request.form.get("confirm") != "yes":
            return render_template(
                "rules_import.html",
                error="Confirm that you reviewed the rules before applying the bundle.",
            ), 400
        raw_bundle = request.form.get("bundle", "")
        if len(raw_bundle.encode("utf-8")) > MAX_RULE_BUNDLE_BYTES:
            return render_template("rules_import.html", error="The bundle exceeds the 512 KiB limit."), 413
        try:
            bundle = json.loads(raw_bundle)
            rules = _validate_rule_bundle(bundle)
        except (json.JSONDecodeError, ValueError) as error:
            return render_template("rules_import.html", error=str(error)), 400

        applied = 0
        failure = None
        for index, rule in enumerate(rules, start=1):
            try:
                result = request_backend(
                    current_app.config["API_URL"],
                    "/api/v1/rules",
                    method="POST",
                    body=json.dumps(rule).encode("utf-8"),
                )
            except (ApiConnectionError, ApiResponseError) as error:
                failure = f"Rule {index}: {error}"
                break
            if result.schema_version != API_SCHEMA_VERSION:
                failure = f"Rule {index}: the API returned an unsupported schema version."
                break
            if not 200 <= result.status < 300:
                try:
                    payload = json.loads(result.body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = {}
                detail = payload.get("error") if isinstance(payload, dict) else None
                failure = f"Rule {index}: {detail or f'API returned HTTP {result.status}.'}"
                break
            applied += 1
        if failure:
            current_app.logger.warning(
                "firewall_rule_bundle_import_partial applied=%s total=%s",
                applied,
                len(rules),
            )
            return render_template(
                "rules_import.html",
                error=f"Import stopped after applying {applied} of {len(rules)} rules. {failure}",
            ), 502
        session.pop("rules_import_csrf", None)
        current_app.logger.info("firewall_rule_bundle_imported applied=%s", applied)
        return render_template(
            "rules_import.html",
            message=f"Successfully added {applied} rules. Existing rules were not removed.",
        )

    raw_bundle = request.files.get("bundle_file")
    if raw_bundle is None:
        return render_template("rules_import.html", error="Choose a JSON bundle to preview."), 400
    content = raw_bundle.stream.read(MAX_RULE_BUNDLE_BYTES + 1)
    if len(content) > MAX_RULE_BUNDLE_BYTES:
        return render_template("rules_import.html", error="The bundle exceeds the 512 KiB limit."), 413
    try:
        bundle = json.loads(content.decode("utf-8"))
        rules = _validate_rule_bundle(bundle)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return render_template("rules_import.html", error=f"Invalid firewall bundle: {error}"), 400
    csrf_token = secrets.token_urlsafe(32)
    session["rules_import_csrf"] = csrf_token
    return render_template(
        "rules_import.html",
        preview_rules=rules,
        bundle_json=json.dumps(bundle, separators=(",", ":")),
        csrf_token=csrf_token,
        omitted_unsupported_rules=bundle.get("omitted_unsupported_rules", 0),
    )


@pages.get("/system")
def system_page():
    """Render read-only host and backend management information.

    Returns:
        Rendered system-management HTML, converted to an HTTP response.
    """
    return render_template("system.html", **_system_context())


@pages.get("/system/logs")
def system_logs_page():
    """Render recent logs grouped by backend-provided source.

    Returns:
        Rendered system logs HTML, converted to an HTTP response.
    """
    logs, error = _load("/api/v1/logs")
    sources = logs.get("sources", []) if isinstance(logs, dict) else []
    if not isinstance(sources, list):
        sources = []
    return render_template(
        "system_logs.html",
        sources=sources,
        error=error,
        api_connected=error is None,
    )


@pages.route("/config", methods=["GET", "POST"])
def config_page():
    """Render or update the dashboard's C++ API connection setting.

    Returns:
        A pair of (rendered HTML, HTTP status code) for Flask to return.
    """
    api_url = current_app.config["API_URL"]
    message = ""
    message_type = ""
    status = 200
    if request.method == "POST":
        submitted_url = valid_api_url(request.form.get("api_url"))
        if submitted_url is None:
            current_app.logger.warning("connection_setting_rejected reason=invalid_url")
            message, message_type, status = "Enter a valid HTTP or HTTPS API base URL.", "error", 400
        elif request.form.get("action") == "test":
            connected, message = test_api_connection(submitted_url)
            message_type = "success" if connected else "error"
            log_method = current_app.logger.info if connected else current_app.logger.warning
            log_method("connection_test completed result=%s", "success" if connected else "failed")
            api_url = submitted_url
        else:
            try:
                save_api_url(Path(current_app.config["CONFIG_PATH"]), submitted_url)
            except OSError:
                current_app.logger.exception("connection_setting_save_failed")
                message, message_type, status = "Unable to save connection settings.", "error", 500
            else:
                current_app.config["API_URL"] = submitted_url
                api_url = submitted_url
                message, message_type = "Connection saved.", "success"
                current_app.logger.info("connection_setting_saved")

    return render_template(
        "config.html",
        api_url=api_url,
        message=message,
        message_type=message_type,
    ), status
