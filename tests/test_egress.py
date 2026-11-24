"""Egress coverage tests (v0.2.1, Codex review #1): test the FINAL outbound
request from both adapters — a detector cannot protect a field it never sees.

The mock upstream records exactly what it receives; assertions run against the
recorded payload, not the gateway's own idea of what it sent."""
import http.server
import json
import os
import threading
import unittest
import urllib.request

from anon_gw.classes import Classes
from anon_gw.core import Gateway
from anon_gw.secrets import SecretLeak
from anon_gw.vault import Vault

IDENTITY_MARKS = ["Alex", "/home/dev", "10.0.0.5", "devbox.lan",
                  "ray@example.com"]


def sample_key():
    return "sk-" + "a1b2c3d4e5f6a7b8c9d0"


class MockUpstream(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        MockUpstream.received.append(json.loads(raw))
        reply = {"id": "m", "choices": [{"message": {"role": "assistant",
                                                     "content": "ok"}}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


class EgressCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstream)
        cls.upstream_port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        # gateway against a tempfile vault, identity-laden defaults
        import tempfile
        fd, cls.vault_path = tempfile.mkstemp(suffix=".json", dir="/tmp")
        os.close(fd)
        os.unlink(cls.vault_path)
        cls.gateway = Gateway(
            project="egress-test",
            vault=Vault(vault_path=cls.vault_path, project="egress-test"),
            classes=Classes(project="egress-test", path="/nonexistent"),
            extra_names=["Alex"])

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def _send(self, body):
        MockUpstream.received.clear()
        payload, n, used, stripped, classes = self.gateway.outbound_json(body)
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.upstream_port}/v1/chat/completions",
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
        return MockUpstream.received[0], n, used, stripped, classes

    def test_no_identity_in_forwarded_payload(self):
        body = {"messages": [
            {"role": "system", "content": "You help Alex with ops on devbox.lan."},
            {"role": "user", "content": "Alex's work lives at /home/dev/evald (10.0.0.5), mail ray@example.com"},
        ]}
        sent, _, _, _, _ = self._send(body)
        s = json.dumps(sent)
        for mark in IDENTITY_MARKS:
            self.assertNotIn(mark, s, f"identity leaked to provider: {mark}")

    def test_system_and_user_fields_both_covered(self):
        # every accepted field: system role, user role, content-part lists
        body = {"messages": [
            {"role": "system", "content": "host is devbox.lan"},
            {"role": "user", "content": [
                {"type": "text", "text": "path /home/dev/secret.txt"}]},
        ]}
        sent, _, _, _, _ = self._send(body)
        s = json.dumps(sent)
        self.assertNotIn("devbox.lan", s)
        self.assertNotIn("/home/dev", s)

    def test_alpha_never_forwarded(self):
        body = {"messages": [{"role": "user",
                              "content": "use <<alpha>>grid 1% dips<<</alpha>> please"}]}
        sent, _, _, stripped, classes = self._send(body)
        self.assertNotIn("grid 1% dips", json.dumps(sent))
        self.assertEqual(stripped, 1)
        self.assertEqual(classes, ["alpha"])

    def test_credentials_fail_closed(self):
        body = {"messages": [{"role": "user", "content": "key " + sample_key()}]}
        with self.assertRaises(SecretLeak):
            self.gateway.outbound_json(body)

    def test_unsupported_fields_rejected(self):
        body = {"messages": [{"role": "assistant", "name": "helper",
                              "content": "hi"}]}
        with self.assertRaises(ValueError):
            self.gateway.outbound_json(body)

    def test_tool_result_content_parts_covered(self):
        # tool-role messages are plain content strings — must be covered too
        body = {"messages": [
            {"role": "user", "content": "hi Alex"},
            {"role": "tool", "content": "output from /home/dev/tool.log"},
        ]}
        sent, _, _, _, _ = self._send(body)
        s = json.dumps(sent)
        self.assertNotIn("/home/dev", s)

    def test_cli_outbound_clean(self):
        text = ("Review Alex's packet on devbox.lan: paths under /home/dev,\n"
                "mail ray@example.com, alpha <<alpha>>1% grid<<</alpha>>.")
        out, n, used, stripped, classes = self.gateway.outbound(text)
        for mark in IDENTITY_MARKS:
            self.assertNotIn(mark, out)
        self.assertNotIn("1% grid", out)
        self.assertIn("[anon-gw: alpha withheld]", out)


if __name__ == "__main__":
    unittest.main()
