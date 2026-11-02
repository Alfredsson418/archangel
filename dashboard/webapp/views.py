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
)
from .page_data import BackendSessionExpired, load, load_all
from .firewall_rules import (
    MAX_IMPORTED_RULES,
    MAX_RULE_BUNDLE_BYTES,
    MAX_RULE_BUNDLE_SIZE_TEXT,
    describe_rule,
    firewall_status,
    portable_bundle,
    rules_from,
    ruleset_shape_error,
    validate_rule_bundle,
)
from .formatting import host_context


pages = Blueprint("pages", __name__)
# Mirror the backend's credential limits (AppConfigLimits::MAX_USERNAME_LENGTH
# and AppConfigLimits::MAX_PASSWORD_BYTES) so oversized input is rejected
# before it is sent. The backend remains authoritative.
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_BYTES = 512
# Backend user IDs are UUIDs; anything else is rejected before it reaches the log.
ACTOR_ID = re.compile(r"[0-9A-Fa-f-]{1,64}")
SORTABLE_RULE_FIELDS = ("family", "table", "chain", "handle", "expr")


@pages.errorhandler(BackendSessionExpired)
def _backend_session_expired(_error):
    """Send the user back to sign in after the backend revoked the session.

    Returns:
        A redirect to the login page that preserves the requested path.
    """
    target = request.full_path if request.query_string else request.path
    return redirect(url_for("pages.login", next=target, expired="1"))


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


def _dashboard_context():
    """Build the overview from backend, firewall, and host-health data.

    Returns:
        A dictionary of values consumed by the overview template.
    """
    payloads, errors, connected = load_all("/api/v1/rules", "/api/v1/system", "/status/info")
    status_label, active_base_chains = firewall_status(payloads["/api/v1/rules"])
    return {
        **host_context(payloads["/api/v1/system"], payloads["/status/info"]),
        "firewall_status": status_label,
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
    payloads, errors, connected = load_all("/api/v1/system", "/status/info")
    return {
        **host_context(payloads["/api/v1/system"], payloads["/status/info"]),
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
                response = current_app.config["API_CLIENT"].request(
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
                    and ACTOR_ID.fullmatch(identity["id"])
                ):
                    session.clear()
                    session["access_token"] = token
                    # Kept only to attribute audit records; never used for authorization.
                    session["actor_id"] = identity["id"]
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
            response = current_app.config["API_CLIENT"].request(
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
    ruleset, error = load("/api/v1/rules")
    if error is None:
        error = ruleset_shape_error(ruleset)
    rules = rules_from(ruleset) if error is None else []
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
        firewall_result=session.pop("firewall_result", None),
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
    ruleset, error = load("/api/v1/rules")
    if error:
        return render_template("rules.html", rules=[], error=error), 502
    shape_error = ruleset_shape_error(ruleset)
    if shape_error:
        return render_template("rules.html", rules=[], error=shape_error), 502
    bundle, skipped = portable_bundle(ruleset)
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
            rules = validate_rule_bundle(bundle)
        except (json.JSONDecodeError, ValueError) as error:
            return render_template("rules_import.html", error=str(error)), 400

        applied = 0
        failure = None
        for index, rule in enumerate(rules, start=1):
            try:
                result = current_app.config["API_CLIENT"].request(
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
        rules = validate_rule_bundle(bundle)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return render_template("rules_import.html", error=f"Invalid firewall bundle: {error}"), 400
    return render_template(
        "rules_import.html",
        preview_rules=[dict(rule, description=describe_rule(rule)) for rule in rules],
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
    logs, error = load("/api/v1/logs")
    sources = logs.get("sources", []) if isinstance(logs, dict) else []
    if not isinstance(sources, list):
        sources = []
    return render_template(
        "system_logs.html",
        sources=sources,
        error=error,
        api_connected=error is None,
    )


@pages.get("/api-connection")
def api_connection_page():
    """Render the deployment-selected API address without allowing browser edits.

    Returns:
        A pair of (rendered HTML, HTTP status code) for Flask to return.
    """
    return render_template(
        "api_connection.html",
        api_url=current_app.config["API_URL"],
        api_url_source="ARCHANGEL_API_URL" if current_app.config.get(
            "API_URL_FROM_ENV"
        ) else "built-in default",
    )
