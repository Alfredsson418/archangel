import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, render_template, request


DEFAULT_API_URL = os.getenv("ARCHANGEL_API_URL", "http://127.0.0.1:8080").rstrip("/")
CONFIG_PATH = Path(os.getenv(
    "ARCHANGEL_WEB_CONFIG",
    Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "archangel" / "web.json",
))


def valid_api_url(value):
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip("/")
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    if parsed.query or parsed.fragment:
        return None
    return value


def load_api_url():
    try:
        saved = json.loads(CONFIG_PATH.read_text()).get("api_url")
    except (OSError, json.JSONDecodeError, AttributeError):
        saved = None
    return valid_api_url(saved) or valid_api_url(DEFAULT_API_URL) or "http://127.0.0.1:8080"


app = Flask(__name__)
app.config["API_URL"] = load_api_url()
app.config["CONFIG_PATH"] = CONFIG_PATH


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/rules")
def rules_page():
    request_to_api = Request(
        f"{app.config['API_URL']}/api/v1/rules",
        headers={"Accept": "application/json"},
    )
    try:
        with urlopen(request_to_api, timeout=10) as upstream:
            ruleset = json.loads(upstream.read())
        entries = ruleset.get("nftables", [])
        rules = [entry["rule"] for entry in entries if isinstance(entry, dict) and "rule" in entry]
        error = None
    except HTTPError as exception:
        rules = []
        error = f"The API returned HTTP {exception.code}."
    except json.JSONDecodeError:
        rules = []
        error = "The API returned invalid JSON."
    except (URLError, TimeoutError, OSError) as exception:
        detail = getattr(exception, "reason", exception)
        rules = []
        error = f"The C++ API is unavailable: {detail}"

    return render_template("rules.html", rules=rules, error=error)


@app.get("/config")
@app.post("/config")
def config_page():
    api_url = app.config["API_URL"]
    if request.method == "POST":
        submitted_url = valid_api_url(request.form.get("api_url"))
        if submitted_url is None:
            return render_config(api_url, "Enter a valid HTTP or HTTPS API base URL.", "error"), 400

        if request.form.get("action") == "test":
            ok, message = test_api_connection(submitted_url)
            return render_config(submitted_url, message, "success" if ok else "error")

        path = Path(app.config["CONFIG_PATH"])
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"api_url": submitted_url}) + "\n")
        except OSError:
            return render_config(api_url, "Unable to save connection settings.", "error"), 500

        app.config["API_URL"] = submitted_url
        return render_config(submitted_url, "Connection saved.", "success")

    return render_config(api_url)


def render_config(api_url, message="", message_type=""):
    return render_template(
        "config.html",
        api_url=api_url,
        message=message,
        message_type=message_type,
    )


def test_api_connection(api_url):
    upstream_request = Request(
        f"{api_url}/api/v1/rules",
        headers={"Accept": "application/json"},
    )
    try:
        with urlopen(upstream_request, timeout=5) as upstream:
            if 200 <= upstream.status < 300:
                return True, "Connection successful. The API returned the active ruleset."
            return False, f"The API responded with HTTP {upstream.status}."
    except HTTPError as error:
        return False, f"The API responded with HTTP {error.code}."
    except (URLError, TimeoutError, OSError) as error:
        detail = getattr(error, "reason", error)
        return False, f"The API could not be reached: {detail}"


def proxy_api(path):
    upstream_request = Request(
        f"{app.config['API_URL']}{path}",
        headers={"Accept": "application/json"},
    )
    try:
        with urlopen(upstream_request, timeout=10) as upstream:
            return Response(
                upstream.read(),
                status=upstream.status,
                content_type=upstream.headers.get("Content-Type", "application/json"),
            )
    except HTTPError as error:
        return Response(
            error.read(),
            status=error.code,
            content_type=error.headers.get("Content-Type", "application/json"),
        )
    except (URLError, TimeoutError, OSError) as error:
        detail = getattr(error, "reason", error)
        return jsonify({"error": "C++ API is unavailable", "detail": str(detail)}), 502


@app.get("/api/v1/rules")
def rules():
    return proxy_api("/api/v1/rules")


@app.get("/api/v1/stats")
def statistics():
    return proxy_api("/api/v1/stats")


@app.get("/api/v1/system")
def system_statistics():
    return proxy_api("/api/v1/system")


if __name__ == "__main__":
    app.run(
        host=os.getenv("WEB_HOST", "127.0.0.1"),
        port=int(os.getenv("WEB_PORT", "5000")),
        debug=False,
    )
