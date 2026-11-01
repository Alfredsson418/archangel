import json
import re
import sqlite3
import stat
from unittest.mock import patch

from server import app

from .helpers import DashboardTestCase, UpstreamResponse


class DashboardAuthenticationTests(DashboardTestCase):
    def setUp(self):
        super().setUp()
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["_csrf_token"] = "test-csrf-token"

    def test_protected_pages_require_dashboard_login(self):
        for path in ("/", "/rules", "/system", "/system/logs", "/api-connection"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])
                response.close()

    @patch("webapp.api_client.urlopen")
    def test_login_keeps_backend_token_server_side_and_rotates_cookie(
        self, urlopen
    ):
        urlopen.return_value = UpstreamResponse(
            {
                "access_token": "backend-session-secret",
                "token_type": "Bearer",
                "identity": {
                    "id": "3f2b8c1e-5d4a-4e7b-9c1f-2a6d8e0b7c45",
                    "username": "operator",
                    "role": "operator",
                },
            }
        )
        login_page = self.client.get("/login?next=/rules")
        self.assertEqual(login_page.status_code, 200)
        csrf = re.search(
            rb'name="csrf_token" value="([^"]+)"', login_page.data
        ).group(1).decode()
        before_cookie = login_page.headers.get("Set-Cookie")
        login_page.close()

        response = self.client.post(
            "/login?next=/rules",
            data={
                "csrf_token": csrf,
                "username": "operator",
                "password": "a submitted password",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/rules")
        after_cookie = response.headers.get("Set-Cookie")
        self.assertNotEqual(before_cookie, after_cookie)
        self.assertNotIn("backend-session-secret", after_cookie)
        response.close()

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8080/api/v1/auth/login")
        self.assertEqual(
            json.loads(request.data),
            {"username": "operator", "password": "a submitted password"},
        )
        headers = {name.lower(): value for name, value in request.headers.items()}
        self.assertNotIn("authorization", headers)

        with self.client.session_transaction() as browser_session:
            self.assertEqual(
                browser_session["access_token"], "backend-session-secret"
            )
            self.assertNotIn("identity", browser_session)
            self.assertEqual(
                browser_session["actor_id"], "3f2b8c1e-5d4a-4e7b-9c1f-2a6d8e0b7c45"
            )
            self.assertNotIn("username", browser_session)
            self.assertNotIn("role", browser_session)

        database = app.config["SESSION_DATABASE"]
        connection = sqlite3.connect(database)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM web_sessions"
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()
        self.assertIn(b"backend-session-secret", database.read_bytes())
        self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)

    @patch("webapp.api_client.urlopen")
    def test_login_rejects_identity_with_unsafe_actor_id(self, urlopen):
        urlopen.return_value = UpstreamResponse(
            {
                "access_token": "backend-session-secret",
                "identity": {"id": "x forged=1", "username": "operator", "role": "operator"},
            }
        )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["_csrf_token"] = "test-csrf-token"
        response = self.client.post(
            "/login",
            data={"csrf_token": "test-csrf-token", "username": "operator", "password": "secret"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The backend rejected the sign-in request.", response.data)
        response.close()
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("access_token", browser_session)
            self.assertNotIn("actor_id", browser_session)

    @patch("webapp.api_client.urlopen")
    def test_logout_revokes_backend_token_and_clears_session(self, urlopen):
        urlopen.return_value = UpstreamResponse(b"", status=204)
        with self.client.session_transaction() as browser_session:
            browser_session["access_token"] = "test-api-access-token"
        response = self.client.post(
            "/logout", data={"csrf_token": self.csrf_token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url, "http://127.0.0.1:8080/api/v1/auth/logout"
        )
        headers = {name.lower(): value for name, value in request.headers.items()}
        self.assertEqual(
            headers["authorization"], "Bearer test-api-access-token"
        )
        response.close()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        response.close()

    def test_all_state_changing_requests_require_csrf_and_same_origin(self):
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)
        response.close()
        response = self.client.post(
            "/logout",
            data={"csrf_token": self.csrf_token()},
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(response.status_code, 403)
        response.close()

    def test_unchanged_session_is_not_rewritten(self):
        with self.client.session_transaction() as browser_session:
            browser_session["access_token"] = "test-api-access-token"
        first = self.client.get("/api-connection")
        self.assertEqual(first.status_code, 200)
        first.close()

        response = self.client.get("/api-connection")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.headers.get("Set-Cookie"))
        response.close()

    @patch("webapp.api_client.urlopen")
    def test_login_limits_match_validation_and_count_password_bytes(self, urlopen):
        login_page = self.client.get("/login")
        self.assertIn(b'maxlength="64"', login_page.data)
        self.assertIn(b'maxlength="512"', login_page.data)
        login_page.close()

        # 200 three-byte characters fit the character limit but not the
        # backend's 512-byte bound, so they must not be sent.
        response = self.client.post(
            "/login",
            data={
                "csrf_token": "test-csrf-token",
                "username": "operator",
                "password": "\u20ac" * 200,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enter a valid username and password.", response.data)
        urlopen.assert_not_called()
        response.close()

    def test_login_rejects_external_next_redirect(self):
        response = self.client.get("/login?next=https://attacker.example")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'action="/login?next=/"', response.data)
        response.close()
