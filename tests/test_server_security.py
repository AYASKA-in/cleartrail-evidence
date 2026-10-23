"""Local-service capability, protocol-abuse, and snapshot regression tests."""
import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cleartrail.core import Store, collect_run
from cleartrail.server import MAX_BODY_BYTES, MAX_REQUEST_THREADS, create_server


class LocalServerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "local.sqlite3")
        self.run = collect_run(self.store, {}, True)
        self.server = create_server(self.store, {"organization": "Example", "providers": {
            "github": {"org": "example", "token": "secret-provider-token"}}}, demo=True, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.cookie = self.csrf = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, path, method="GET", data=None, headers=None, auth=True):
        request_headers = {}
        if method == "POST":
            request_headers.update({"Origin": self.base, "Content-Type": "application/json"})
        if auth and self.cookie:
            request_headers["Cookie"] = self.cookie
            if method == "POST":
                request_headers["X-ClearTrail-Token"] = self.csrf
        request_headers.update(headers or {})
        body = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=request_headers)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def login(self):
        status, headers, data = self.request("/api/session", "POST", {"token": self.server.bootstrap_token}, auth=False)
        self.assertEqual(status, 200, data)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = json.loads(data)["csrf"]
        return headers

    def raw(self, lines, body=b""):
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as sock:
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            result = b""
            while True:
                part = sock.recv(65536)
                if not part:
                    return result
                result += part

    def test_sensitive_reads_require_capability(self):
        for path in ("/api/state", "/api/export", "/api/report", "/api/csv", "/api/state?since=" + self.run["id"]):
            with self.subTest(path=path):
                status, _, data = self.request(path)
                self.assertEqual(status, 401)
                self.assertNotIn(b"Example", data)
                self.assertNotIn(self.run["id"].encode(), data)

    def test_health_has_no_account_information(self):
        status, _, data = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), {"status": "ok"})

    def test_static_shell_contains_no_launch_capability(self):
        for path in ("/", "/app.js", "/style.css"):
            status, headers, data = self.request(path)
            self.assertEqual(status, 200)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Frame-Options"], "DENY")
            self.assertNotIn(self.server.bootstrap_token.encode(), data)

    def test_session_cookie_and_private_state(self):
        headers = self.login()
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        status, headers, data = self.request("/api/state")
        self.assertEqual(status, 200)
        state = json.loads(data)
        self.assertEqual(state["csrf"], self.csrf)
        self.assertNotIn("secret-provider-token", data.decode())
        self.assertNotIn(self.server.bootstrap_token, data.decode())
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")

    def test_bad_and_non_ascii_launch_capabilities_fail_cleanly(self):
        for token in ("wrong", "é" * 43, "\ud800", [1], None, 12, {}):
            with self.subTest(token=repr(token)):
                status, _, data = self.request("/api/session", "POST", {"token": token})
                self.assertEqual(status, 403, data)

    def test_launch_capability_is_reusable_for_another_browser(self):
        self.login()
        first_cookie, first_csrf = self.cookie, self.csrf
        self.login()
        self.assertNotEqual(self.cookie, first_cookie)
        self.assertNotEqual(self.csrf, first_csrf)
        status, _, _ = self.request("/api/logout", "POST", {}, headers={"X-ClearTrail-Token": first_csrf})
        self.assertEqual(status, 403)

    def test_exact_origin_matches_host(self):
        for headers in ({"Origin": "https://evil.example"}, {"Origin": "null"},
                        {"Origin": self.base.replace("127.0.0.1", "localhost")}, {"Host": "evil.example"},
                        {"Sec-Fetch-Site": "same-site"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                status, _, _ = self.request("/api/session", "POST", {"token": self.server.bootstrap_token}, headers=headers)
                self.assertEqual(status, 403)

    def test_session_requires_origin(self):
        response = self.raw(["POST /api/session HTTP/1.1", f"Host: 127.0.0.1:{self.server.server_port}",
                             "Content-Length: 2", "Content-Type: application/json"], b"{}")
        self.assertIn(b" 403 ", response.split(b"\r\n", 1)[0])

    def test_mutation_requires_cookie_and_csrf(self):
        self.login()
        for headers in ({"Cookie": ""}, {"X-ClearTrail-Token": ""}, {"X-ClearTrail-Token": "é"}):
            status, _, _ = self.request("/api/scan", "POST", {}, headers=headers)
            self.assertIn(status, (401, 403))

    def test_logout_revokes_session(self):
        self.login()
        status, headers, _ = self.request("/api/logout", "POST", {})
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.request("/api/state")[0], 401)

    def test_session_expiry_is_enforced_server_side(self):
        with patch("cleartrail.server.SESSION_SECONDS", 0):
            self.login()
        self.assertEqual(self.request("/api/state")[0], 401)

    def test_login_attempts_are_rate_limited(self):
        with patch("cleartrail.server.LOGIN_LIMIT", 2):
            self.assertEqual(self.request("/api/session", "POST", {"token": "bad"})[0], 403)
            self.assertEqual(self.request("/api/session", "POST", {"token": "bad"})[0], 403)
            self.assertEqual(self.request("/api/session", "POST", {"token": self.server.bootstrap_token})[0], 429)

    def test_malformed_json_and_duplicate_fields_are_rejected(self):
        for body in (b"[]", b"null", b"1", b"{}x", b"\xff", b'{"token":"a","token":"b"}', b'{"token":NaN}', b"[" * 2000):
            with self.subTest(body=body[:60]):
                status, _, _ = self.request("/api/session", "POST", body)
                self.assertEqual(status, 400)

    def test_body_size_and_media_type_bounds(self):
        self.assertEqual(self.request("/api/session", "POST", b" " * (MAX_BODY_BYTES + 1))[0], 413)
        self.assertEqual(self.request("/api/session", "POST", b"{}", headers={"Content-Type": "text/plain"})[0], 415)

    def test_ambiguous_headers_and_transfer_encoding_are_rejected(self):
        base = ["POST /api/session HTTP/1.1", f"Host: 127.0.0.1:{self.server.server_port}",
                f"Origin: {self.base}", "Content-Type: application/json", "Content-Length: 2"]
        for extra in ("Host: evil.example", "Content-Length: 2", "Origin: " + self.base,
                      "Authorization: a\r\nAuthorization: b", "Cookie: a\r\nCookie: b",
                      "X-ClearTrail-Token: a\r\nX-ClearTrail-Token: b", "Transfer-Encoding: chunked"):
            with self.subTest(extra=extra):
                response = self.raw(base + [extra], b"{}")
                self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])

    def test_bad_lengths_and_missing_lengths_are_rejected(self):
        base = ["POST /api/session HTTP/1.1", f"Host: 127.0.0.1:{self.server.server_port}",
                f"Origin: {self.base}", "Content-Type: application/json"]
        for length in ("-1", "+2", "2,2", "abc", "99999999999999999"):
            response = self.raw(base + ["Content-Length: " + length])
            self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        self.assertIn(b" 411 ", self.raw(base).split(b"\r\n", 1)[0])

    def test_header_block_has_total_budget(self):
        response = self.raw(["GET / HTTP/1.1", f"Host: 127.0.0.1:{self.server.server_port}", "X-Fill: " + "a" * 17000])
        self.assertIn(b" 431 ", response.split(b"\r\n", 1)[0])

    def test_unknown_or_ambiguous_queries_are_rejected(self):
        self.login()
        for path in ("/api/state?token=x", "/api/export?run_id=bad", "/api/export?run_id=" + self.run["id"] + "&run_id=" + self.run["id"],
                     "/api/health?x=1", "/api/state?since=%FF", "/api/%73tate", "/api/state?since="):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 400)

    def test_attestation_does_not_coerce_types(self):
        self.login()
        for data in ({"control_id": "MAN-POLICY", "owner": [], "note": "Reviewed"},
                     {"control_id": "MAN-POLICY", "owner": "Alex", "note": "Reviewed", "extra": "x"},
                     {"control_id": "GH-MFA", "owner": "Alex", "note": "Reviewed"}):
            self.assertEqual(self.request("/api/attest", "POST", data)[0], 400)
        self.assertEqual(self.store.attestations(), {})

    def test_attestation_success(self):
        self.login()
        status, _, _ = self.request("/api/attest", "POST", {"control_id": "MAN-POLICY", "owner": "Alex", "note": "Reviewed policy SEC-01."})
        self.assertEqual(status, 200)
        self.assertIn("MAN-POLICY", self.store.attestations())

    def test_selected_historical_snapshot_is_exported(self):
        self.login()
        with patch.object(self.store, "get_run", return_value=self.run, create=True) as lookup:
            for path in ("/api/export", "/api/report", "/api/csv"):
                self.assertEqual(self.request(path + "?run_id=" + self.run["id"])[0], 200)
            self.assertEqual(lookup.call_count, 3)
            lookup.assert_called_with(self.run["id"])
        with patch.object(self.store, "get_run", return_value=None, create=True):
            self.assertEqual(self.request("/api/report?run_id=run_" + "0" * 16)[0], 404)

    def test_unchanged_state_does_not_load_full_snapshot(self):
        self.login()
        with patch.object(self.store, "latest_id", return_value=self.run["id"], create=True), patch.object(self.store, "latest", side_effect=AssertionError("full read")):
            status, _, data = self.request("/api/state?since=" + self.run["id"])
        self.assertEqual(status, 200, data)
        self.assertTrue(json.loads(data)["unchanged"])
        self.assertIsNone(json.loads(data)["run"])

    def test_collection_cannot_be_started_twice(self):
        self.login()
        release = threading.Event()
        with patch("cleartrail.server.collect_run", side_effect=lambda *args: release.wait(3)):
            try:
                self.assertEqual(self.request("/api/scan", "POST", {})[0], 202)
                self.assertEqual(self.request("/api/scan", "POST", {})[0], 409)
            finally:
                release.set()
                self.server.collection_thread.join(2)

    def test_failed_collection_preserves_previous_snapshot_and_hides_error(self):
        self.login()
        with patch("cleartrail.server.collect_run", side_effect=RuntimeError("secret-test-credential")), self.assertLogs("cleartrail.server", level="WARNING") as captured:
            self.assertEqual(self.request("/api/scan", "POST", {})[0], 202)
            self.server.collection_thread.join(2)
        status, _, data = self.request("/api/state")
        self.assertEqual(status, 200)
        state = json.loads(data)
        self.assertEqual(state["run"]["id"], self.run["id"])
        self.assertEqual(state["job"]["error_code"], "collection_failed")
        self.assertNotIn("secret-test-credential", data.decode() + str(captured.output))

    def test_internal_failure_is_generic_and_correlated(self):
        self.login()
        with patch.object(self.store, "latest", side_effect=RuntimeError("secret-account-token")), self.assertLogs("cleartrail.server", level="WARNING") as captured:
            status, headers, data = self.request("/api/state")
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(data)["request_id"], headers["X-Request-ID"])
        self.assertNotIn("secret-account-token", data.decode() + str(captured.output))

    def test_worker_slots_are_bounded_before_allocation(self):
        for _ in range(MAX_REQUEST_THREADS):
            self.assertTrue(self.server._request_slots.acquire(blocking=False))
        try:
            with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2) as sock:
                try:
                    sock.sendall(f"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n\r\n".encode())
                    self.assertEqual(sock.recv(100), b"")
                except ConnectionResetError:
                    pass
        finally:
            for _ in range(MAX_REQUEST_THREADS):
                self.server._request_slots.release()
        self.assertEqual(self.request("/api/health")[0], 200)

    def test_slow_request_body_times_out(self):
        with patch("cleartrail.server.REQUEST_TIMEOUT_SECONDS", .15):
            response = self.raw(["POST /api/session HTTP/1.1", f"Host: 127.0.0.1:{self.server.server_port}",
                                 f"Origin: {self.base}", "Content-Type: application/json", "Content-Length: 200"], b"{")
        self.assertIn(b" 408 ", response.split(b"\r\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
