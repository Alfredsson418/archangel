from datetime import datetime
from pathlib import Path

from flask import Blueprint, current_app, render_template, request

from .api_client import ApiConnectionError, ApiResponseError, fetch_json, test_api_connection
from .settings import save_api_url, valid_api_url


pages = Blueprint("pages", __name__)


def _load(path):
    try:
        return fetch_json(current_app.config["API_URL"], path), None
    except (ApiConnectionError, ApiResponseError) as error:
        current_app.logger.warning(
            "backend_request_failed path=%s error_type=%s",
            path,
            type(error).__name__,
        )
        return None, str(error)


def _rules_from(ruleset):
    if not isinstance(ruleset, dict):
        return []
    entries = ruleset.get("nftables", [])
    if not isinstance(entries, list):
        return []
    return [entry["rule"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("rule"), dict)]


def _display_bytes(value):
    if value is None:
        return "Unavailable"
    value = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    return f"{value:.0f} {units[unit]}" if unit == 0 else f"{value:.1f} {units[unit]}"


def _dashboard_context():
    ruleset, rules_error = _load("/api/v1/rules")
    statistics, stats_error = _load("/api/v1/stats")
    system, system_error = _load("/api/v1/system")
    errors = [error for error in (rules_error, stats_error, system_error) if error]
    system = system or {}
    statistics = statistics or {}
    loads = system.get("load_average") or []
    cpu_load = " / ".join("—" if value is None else f"{float(value):.2f}" for value in loads[:3]) or "Unavailable"
    return {
        "rules": _rules_from(ruleset)[:8],
        "rules_error": rules_error,
        "statistics": statistics,
        "system": system,
        "errors": errors,
        "api_connected": not errors,
        "last_updated": datetime.now().strftime("%H:%M:%S"),
        "cpu_load": cpu_load,
        "memory_percent": system.get("memory_usage_percent"),
        "memory_detail": f"{_display_bytes(system.get('memory_used_bytes'))} used of {_display_bytes(system.get('memory_total_bytes'))}",
        "disk_percent": system.get("disk_usage_percent"),
        "disk_detail": f"{_display_bytes(system.get('disk_used_bytes'))} used of {_display_bytes(system.get('disk_total_bytes'))}",
    }


@pages.get("/")
def index():
    return render_template("index.html", **_dashboard_context())


@pages.get("/rules")
def rules_page():
    ruleset, error = _load("/api/v1/rules")
    return render_template("rules.html", rules=_rules_from(ruleset), error=error)


@pages.route("/config", methods=["GET", "POST"])
def config_page():
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
