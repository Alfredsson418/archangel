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
    MAX_RULE_BUNDLE_SIZE_TEXT,
    RULE_FAMILIES,
    firewall_status,
    portable_bundle,
    ruleset_shape_error,
)
from . import pending_changes
from .firewall_changes import dormant_tables, rule_tree, select_in_tree
from .formatting import host_context


pages = Blueprint("pages", __name__)
# Mirror the backend's credential limits (AppConfigLimits::MAX_USERNAME_LENGTH
# and AppConfigLimits::MAX_PASSWORD_BYTES) so oversized input is rejected
# before it is sent. The backend remains authoritative.
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_BYTES = 512
# Backend user IDs are UUIDs; anything else is rejected before it reaches the log.
ACTOR_ID = re.compile(r"[0-9A-Fa-f-]{1,64}")
# Mirrors Config::Limits::MAX_CHAIN_PRIORITY; the backend is authoritative.
MAX_CHAIN_PRIORITY = 1000
CHAIN_HOOKS = ("input", "forward", "output", "prerouting", "postrouting")
CHAIN_POLICIES = ("accept", "drop")


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
        "dormant_tables": dormant_tables(payloads["/api/v1/rules"]),
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


def rules_context(*, error=None, firewall_result=None):
    """Load everything the rules page shows.

    Args:
        error: A message to show, such as why a form was rejected.
        firewall_result: The outcome of the last change, shown once.

    Returns:
        A dictionary of template variables.

    Raises:
        BackendSessionExpired: If the backend rejects the session.
    """
    ruleset, load_error = load("/api/v1/rules")
    if load_error is None:
        load_error = ruleset_shape_error(ruleset)
    query = request.args.get("q", "").strip()[:100]
    context = {
        "tree": {"families": [], "total": 0, "matching": 0},
        "selected": {"family": None, "table": None, "chain": None},
        "query": query,
        "error": error or load_error,
        "api_unavailable": load_error is not None,
        "firewall_result": firewall_result,
        "dormant_tables": [],
        "hooks": CHAIN_HOOKS,
        "policies": CHAIN_POLICIES,
        "families": RULE_FAMILIES,
    }
    if load_error is None:
        actor = session.get("actor_id")
        changes = pending_changes.load(actor)["changes"] if isinstance(actor, str) else []
        highlighted = firewall_result.get("highlight", []) if firewall_result else []
        context["tree"] = rule_tree(ruleset, query, highlighted, changes)
        # An explicit choice is remembered, so that returning from a form or a
        # review comes back to the same place.
        wanted = (request.args.get("family"), request.args.get("table"), request.args.get("chain"))
        if not wanted[1]:
            remembered = session.get("rules_selection")
            wanted = remembered if isinstance(remembered, list) else wanted
        context["selected"] = select_in_tree(context["tree"], wanted)
        selected = context["selected"]
        session["rules_selection"] = [selected["family"], selected["table"], selected["chain"]]
        context["dormant_tables"] = dormant_tables(ruleset)
    return context


@pages.get("/rules")
def rules_page():
    """Render a tree of families and tables beside the selected table's chains.

    Returns:
        Rendered rules HTML. The family, table, and chain query parameters
        choose what's shown, and q filters the tree.
    """
    return render_template("rules.html", **rules_context(firewall_result=session.pop("firewall_result", None)))


@pages.get("/rules/export")
def export_rules():
    """Download active Archangel-supported firewall rules as a portable bundle.

    Returns:
        A JSON attachment and a warning header if unsupported rules were omitted.
    """
    ruleset, error = load("/api/v1/rules")
    if error:
        return render_template("rules.html", **rules_context(error=error)), 502
    shape_error = ruleset_shape_error(ruleset)
    if shape_error:
        return render_template("rules.html", **rules_context(error=shape_error)), 502
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
