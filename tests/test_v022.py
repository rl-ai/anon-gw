"""v0.2.2 tests: base-URL mode (anthropic /v1/messages through the real server),
semantic-preserving path replacement, selftest command, audit log."""
import http.server
import json
import os
import tempfile
import threading
import unittest
import urllib.request

from anon_gw.classes import Classes
from anon_gw.core import Gateway
from anon_gw.selftest import run as selftest_run
from anon_gw.vault import Vault


def tmp_path():
    fd, p = tempfile.mkstemp(suffix=".json", dir="/tmp")
    os.close(fd)
    os.unlink(p)
    return p


class MockUpstream(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        MockUpstream.received.append(json.loads(raw))
        body = json.loads(raw)
        parts = []
        for m in body.get("messages", []):
            c = m.get("content")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                parts.extend(b.get("text", "") for b in c if isinstance(b, dict))
        seen = " ".join(parts)
        reply = {"id": "m", "content": [{"type": "text", "text": "noted: " + seen}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


class AnthropicRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockUpstream)
        cls.port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.vault_path = tmp_path()
        cls.gateway = Gateway(
            project="antr-test", vault=Vault(vault_path=cls.vault_path, project="antr-test"),
            classes=Classes(project="antr-test", path="/nonexistent"),
            extra_names=["Alex"])

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()

    def _send(self, body, path="/v1/messages"):
        MockUpstream.received.clear()
        if path == "/v1/messages":
            payload, n, used, s, cls = self.gateway.outbound_anthropic(body)
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        return MockUpstream.received[0], resp

    def test_anthropic_system_and_messages_covered(self):
        body = {"model": "claude-x", "max_tokens": 10,
                "system": "You assist Alex on devbox.lan.",
                "messages": [{"role": "user",
                              "content": [{"type": "text",
                                           "text": "Alex's code is at /home/dev/evald"}]}]}
        sent, _ = self._send(body)
        s = json.dumps(sent)
        self.assertNotIn("Alex", s)
        self.assertNotIn("devbox.lan", s)
        self.assertNotIn("/home/dev", s)

    def test_rehydration_restores_response(self):
        body = {"model": "claude-x", "max_tokens": 10,
                "messages": [{"role": "user", "content": "Alex's path /home/dev/evald"}]}
        _, resp = self._send(body)
        restored = self.gateway.inbound_json(resp)
        self.assertEqual(restored["content"][0]["text"],
                         "noted: Alex's path /home/dev/evald")

    def test_anthropic_tool_content_rejected(self):
        body = {"model": "claude-x", "max_tokens": 10,
                "messages": [{"role": "user", "tool_use": {"id": "1"}, "content": "x"}]}
        with self.assertRaises(ValueError):
            self.gateway.outbound_anthropic(body)


class SemanticPathTests(unittest.TestCase):
    def test_valid_path_replacement_and_rehydrate(self):
        vp = tmp_path()
        v = Vault(vault_path=vp, project="s")
        out, n, used = v.pseudonymize("fix /home/dev/evald/scoring.py imports",
                                      semantic_paths=True)
        # valid path, no username leak
        self.assertNotIn("dev", out)
        self.assertIn("/home/user/evald/scoring.py", out)
        self.assertEqual(v.reidentify(out, only=used),
                         "fix /home/dev/evald/scoring.py imports")
        os.unlink(vp)


class SelftestTests(unittest.TestCase):
    def test_selftest_passes(self):
        self.assertEqual(selftest_run(out=lambda s: None), 0)


class AuditTests(unittest.TestCase):
    def test_audit_log_counts_only(self):
        vp = tmp_path()
        ap = tmp_path()
        gw = Gateway(project="a", vault=Vault(vault_path=vp, project="a"),
                     classes=Classes(project="a", path="/nonexistent"),
                     audit=True, semantic_paths=False)
        gw.audit_path = ap
        gw.outbound("Alex <<alpha>>grid<<</alpha>>", provider="codex")
        entry = json.loads(open(ap).read().strip())
        self.assertEqual(entry["provider"], "codex")
        self.assertEqual(entry["n_pseudonymized"], 1)
        self.assertEqual(entry["classes"], ["alpha"])
        # no payload content in the log
        self.assertNotIn("grid", open(ap).read())
        self.assertNotIn("Alex", open(ap).read())
        os.unlink(vp)
        os.unlink(ap)


if __name__ == "__main__":
    unittest.main()
