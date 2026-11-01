import ipaddress
import json
import re
from datetime import datetime
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    current_app,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .api_client import (
    API_SCHEMA_VERSION,
    ApiConnectionError,
    ApiResponseError,
    fetch_json,
    request_backend,
)


pages = Blueprint("pages", __name__)
RULE_BUNDLE_FORMAT = "archangel-firewall-rules"
RULE_BUNDLE_VERSION = 1
MAX_RULE_BUNDLE_BYTES = 512 * 1024
MAX_RULE_BUNDLE_SIZE_TEXT = f"{MAX_RULE_BUNDLE_BYTES // 1024} KiB"
MAX_IMPORTED_RULES = 1000
# Mirror the backend's credential limits (Auth::MAX_USERNAME_LENGTH and
# Auth::MAX_PASSWORD_BYTES) so oversized input is rejected before it is sent.
# The backend remains authoritative.
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_BYTES = 512
SORTABLE_RULE_FIELDS = ("family", "table", "chain", "handle", "expr")
RULE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
# nftables lists layer-4 protocols by number when no port match implies them.
L4_PROTOCOLS = {"tcp": "tcp", "udp": "udp", 6: "tcp", 17: "udp"}


class BackendSessionExpired(Exception):
    """Raised when the backend rejects the dashboard's stored session."""


@pages.errorhandler(BackendSessionExpired)
def _backend_session_expired(_error):
    """Send the user back to sign in after the backend revoked the session.

    Returns:
        A redirect to the login page that preserves the requested path.
    """
    target = request.full_path if request.query_string else request.path
    return redirect(url_for("pages.login", next=target, expired="1"))


def _fetch(path):
    """Fetch one API JSON resource with the browser session's credential.

    Returns:
        The decoded JSON payload.

    Raises:
        BackendSessionExpired: If the backend rejects the session; the browser
            session is cleared first.
        ApiConnectionError: If the backend cannot be reached.
        ApiResponseError: For other unsuccessful or invalid responses.
    """
    try:
        return fetch_json(
            current_app.config["API_URL"],
            path,
            bearer_token=session.get("access_token"),
        )
    except ApiResponseError as error:
        if error.status == 401:
            session.clear()
            raise BackendSessionExpired from error
        raise


def _load(path):
    """Load one API JSON resource for a rendered page.

    Returns:
        A pair of (decoded payload, None) on success, or (None, error text) if
        the backend request fails.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    try:
        return _fetch(path), None
    except (ApiConnectionError, ApiResponseError) as error:
        return None, str(error)


def _load_all(*paths):
    """Load several API resources, stopping once the backend is unreachable.

    Returns:
        A tuple of (payloads keyed by path, error messages, connected flag).
        Payloads are None for paths that failed or were skipped.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    payloads = dict.fromkeys(paths)
    errors = []
    for path in paths:
        try:
            payloads[path] = _fetch(path)
        except ApiConnectionError as error:
            # Later requests would wait for the same unreachable backend.
            errors.append(str(error))
            return payloads, errors, False
        except ApiResponseError as error:
            errors.append(str(error))
    return payloads, errors, True


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
            hashable = isinstance(right, (str, int)) and not isinstance(right, bool)
            l4_protocol = L4_PROTOCOLS.get(right) if hashable else None
            if (
                not isinstance(meta, dict)
                or meta.get("key") != "l4proto"
                or l4_protocol is None
                or protocol is not None
            ):
                return None
            protocol = l4_protocol
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

    # nftables omits the l4proto match when a port match already implies it.
    protocol = protocol or matches.get("port_protocol")
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


@pages.context_processor
def _input_limits():
    """Expose input limits to templates so forms and hints match validation.

    Returns:
        Template variables for credential and rule-bundle limits.
    """
    return {
        "max_username_length": MAX_USERNAME_LENGTH,
        "max_password_bytes": MAX_PASSWORD_BYTES,
        "max_bundle_size": MAX_RULE_BUNDLE_SIZE_TEXT,
        "max_imported_rules": MAX_IMPORTED_RULES,
    }


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


def _host_context(system, backend):
    """Format host and backend metrics shared by the overview and system pages.

    Returns:
        A dictionary of display values consumed by the page templates.
    """
    system = system or {}
    backend = backend or {}
    loads = system.get("load_average") or []
    cpu_load = " / ".join("—" if value is None else f"{float(value):.2f}" for value in loads[:3]) or "Unavailable"
    return {
        "system": system,
        "backend": backend,
        "cpu_load": cpu_load,
        "host_uptime": _format_uptime(system.get("uptime_seconds")),
        "backend_uptime": _format_uptime(backend.get("uptime_seconds")),
        "memory_percent": system.get("memory_usage_percent"),
        "memory_detail": f"{_display_bytes(system.get('memory_used_bytes'))} used of {_display_bytes(system.get('memory_total_bytes'))}",
        "disk_percent": system.get("disk_usage_percent"),
        "disk_detail": f"{_display_bytes(system.get('disk_used_bytes'))} used of {_display_bytes(system.get('disk_total_bytes'))}",
    }


def _dashboard_context():
    """Build the overview from backend, firewall, and host-health data.

    Returns:
        A dictionary of values consumed by the overview template.
    """
    payloads, errors, connected = _load_all("/api/v1/rules", "/api/v1/system", "/status/info")
    firewall_status, active_base_chains = _firewall_status(payloads["/api/v1/rules"])
    return {
        **_host_context(payloads["/api/v1/system"], payloads["/status/info"]),
        "firewall_status": firewall_status,
        "active_base_chains": active_base_chains,
        "errors": errors,
        "api_connected": connected,
        "last_updated": datetime.now().strftime("%H:%M:%S"),
    }


def _system_context():
    """Build read-only host and Archangel process management information.

    Returns:
        A dictionary of diagnostic data consumed by the system page.
    """
    payloads, errors, connected = _load_all("/api/v1/system", "/status/info")
    return {
        **_host_context(payloads["/api/v1/system"], payloads["/status/info"]),
        "errors": errors,
        "api_connected": connected,
    }


@pages.get("/healthz")
def healthz():
    """Report that the dashboard process is serving requests.

    Used by the container health check; it does not contact the backend or
    touch the session store.

    Returns:
        An empty HTTP 204 response.
    """
    return "", 204


@pages.get("/")
def index():
    """Render the overview page with current backend data.

    Returns:
        Rendered overview HTML, converted to an HTTP response by Flask.
    """
    return render_template("index.html", **_dashboard_context())


def _safe_next_path(value):
    """Return a local redirect target or the dashboard overview path."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return url_for("pages.index")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return url_for("pages.index")
    return value


@pages.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate with the backend and keep its token server-side.

    Returns:
        A login page or a redirect after successful backend authentication.
    """
    error = ""
    next_path = _safe_next_path(request.values.get("next"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if (
            not username
            or not password
            or len(username) > MAX_USERNAME_LENGTH
            or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES
        ):
            error = "Enter a valid username and password."
        else:
            try:
                response = request_backend(
                    current_app.config["API_URL"],
                    "/api/v1/auth/login",
                    method="POST",
                    body=json.dumps(
                        {"username": username, "password": password}
                    ).encode("utf-8"),
                )
                payload = json.loads(response.body) if response.body else {}
            except (ApiConnectionError, ApiResponseError, json.JSONDecodeError):
                current_app.logger.warning("dashboard_login_failed reason=backend_unavailable")
                error = "Unable to contact the configured backend."
            else:
                identity = payload.get("identity") if isinstance(payload, dict) else None
                token = payload.get("access_token") if isinstance(payload, dict) else None
                if (
                    response.status == 200
                    and response.schema_version == API_SCHEMA_VERSION
                    and isinstance(token, str)
                    and isinstance(identity, dict)
                    and all(
                        isinstance(identity.get(field), str)
                        for field in ("id", "username", "role")
                    )
                ):
                    session.clear()
                    session["access_token"] = token
                    session.rotate()
                    current_app.logger.info("dashboard_login_succeeded")
                    return redirect(next_path)
                if response.status == 429:
                    error = "Too many sign-in attempts. Wait before trying again."
                elif response.status == 401:
                    error = "Username or password is incorrect."
                else:
                    error = "The backend rejected the sign-in request."
                current_app.logger.warning(
                    "dashboard_login_failed status=%s", response.status
                )
    return render_template("login.html", error=error, next_path=next_path)


@pages.post("/logout")
def logout():
    """Revoke the backend token and clear the server-side browser session."""
    token = session.get("access_token")
    logout_failed = False
    if isinstance(token, str):
        try:
            response = request_backend(
                current_app.config["API_URL"],
                "/api/v1/auth/logout",
                method="POST",
                bearer_token=token,
            )
            logout_failed = response.status != 204
        except ApiConnectionError:
            logout_failed = True
    session.clear()
    session.rotate()
    if logout_failed:
        current_app.logger.warning("dashboard_logout_backend_revoke_failed")
    return redirect(url_for("pages.login", logged_out="1"))


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
        if request.form.get("confirm") != "yes":
            return render_template(
                "rules_import.html",
                error="Confirm that you reviewed the rules before applying the bundle.",
            ), 400
        raw_bundle = request.form.get("bundle", "")
        if len(raw_bundle.encode("utf-8")) > MAX_RULE_BUNDLE_BYTES:
            return render_template("rules_import.html", error=f"The bundle exceeds the {MAX_RULE_BUNDLE_SIZE_TEXT} limit."), 413
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
                    bearer_token=session.get("access_token"),
                )
            except (ApiConnectionError, ApiResponseError) as error:
                failure = f"Rule {index}: {error}"
                break
            if result.status == 401:
                current_app.logger.warning(
                    "firewall_rule_bundle_import_partial applied=%s total=%s",
                    applied,
                    len(rules),
                )
                session.clear()
                raise BackendSessionExpired
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
        return render_template("rules_import.html", error=f"The bundle exceeds the {MAX_RULE_BUNDLE_SIZE_TEXT} limit."), 413
    try:
        bundle = json.loads(content.decode("utf-8"))
        rules = _validate_rule_bundle(bundle)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return render_template("rules_import.html", error=f"Invalid firewall bundle: {error}"), 400
    return render_template(
        "rules_import.html",
        preview_rules=rules,
        bundle_json=json.dumps(bundle, separators=(",", ":")),
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


@pages.get("/config")
def config_page():
    """Render the deployment-selected API address without allowing browser edits.

    Returns:
        A pair of (rendered HTML, HTTP status code) for Flask to return.
    """
    return render_template(
        "config.html",
        api_url=current_app.config["API_URL"],
        api_url_source="ARCHANGEL_API_URL" if current_app.config.get(
            "API_URL_FROM_ENV"
        ) else "built-in default",
    )
