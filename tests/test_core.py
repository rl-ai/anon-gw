import json
import os
import tempfile
import unittest

from anon_gw.classes import Classes
from anon_gw.core import Gateway
from anon_gw.secrets import SecretLeak, scan
from anon_gw.transport import check_upstream
from anon_gw.vault import Vault


def sample_key():
    # synthetic fixture built by concatenation so secret scanners do not
    # redact the test source itself
    return "sk-" + "a1b2c3d4e5f6a7b8c9d0"


def tmp_path():
    fd, p = tempfile.mkstemp(suffix=".json", dir="/tmp")
    os.close(fd)
    os.unlink(p)
    return p


class ClassesTests(unittest.TestCase):
    def test_marker_strip(self):
        c = Classes(project="t", path="/nonexistent")
        text = "plan: <<alpha>>buy dips at 1% grid<<</alpha>> done"
        out, n, classes = c.strip(text)
        self.assertNotIn("buy dips", out)
        self.assertEqual(n, 1)
        self.assertEqual(classes, ["alpha"])

    def test_schema_strip(self):
        p = tmp_path()
        with open(p, "w") as fh:
            json.dump({"default": {"results": ["pnl[:= ]+[-+0-9.]+"]}}, fh)
        c = Classes(project="t", path=p)
        out, n, classes = c.strip("results pnl: +4200 today")
        self.assertNotIn("4200", out)
        self.assertEqual(classes, ["results"])

    def test_project_scoped_schema(self):
        p = tmp_path()
        with open(p, "w") as fh:
            json.dump({"projects": {"t": {"alpha": ["secret-[a-z]+"]}}}, fh)
        c = Classes(project="t", path=p)
        out, _, _ = c.strip("the secret-grid works")
        self.assertNotIn("secret-grid", out)
        c2 = Classes(project="other", path=p)
        out2, n2, _ = c2.strip("the secret-grid works")
        self.assertEqual(n2, 0)
        self.assertIn("secret-grid", out2)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.path = tmp_path()
        self.v = Vault(vault_path=self.path, project="t")

    def test_deterministic_within_project(self):
        a = self.v.pseudonym("Alex", "person")
        b = self.v.pseudonym("Alex", "person")
        self.assertEqual(a, b)
        self.assertNotIn("Alex", a)

    def test_rotation_changes_pseudonyms(self):
        a = self.v.pseudonym("Alex", "person")
        self.v.rotate()
        b = self.v.pseudonym("Alex", "person")
        self.assertNotEqual(a, b)

    def test_roundtrip(self):
        text = "Contact Alex at 10.0.0.5 about /home/dev/work."
        out, n, used = self.v.pseudonymize(text)
        self.assertNotIn("Alex", out)
        self.assertNotIn("10.0.0.5", out)
        self.assertNotIn("/home/dev", out)
        self.assertGreaterEqual(n, 3)
        self.assertEqual(self.v.reidentify(out, only=used), text)

    def test_projects_isolated(self):
        v2 = Vault(vault_path=self.path, project="other")
        out2, _, _ = v2.pseudonymize("Alex works.")
        self.assertEqual(v2.reidentify(out2), "Alex works.")
        self.assertIn("person-", out2)

    def test_no_overlap_shadowing(self):
        # path + email in one text must not leak fragments (review finding 10)
        text = "see /home/alicex.com/docs and mail bob@example.com"
        out, _, used = self.v.pseudonymize(text)
        self.assertEqual(self.v.reidentify(out, only=used), text)

    def test_scoped_reidentify(self):
        out2, _, used2 = self.v.pseudonymize("Alex again")
        self.assertIn("Alex", self.v.reidentify(out2, only=used2))
        self.assertIn("Alex", self.v.reidentify(out2))

    def test_vault_file_permissions(self):
        self.v.pseudonymize("Alex")  # force a save
        self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)


class SecretTests(unittest.TestCase):
    def test_blocks_keys(self):
        with self.assertRaises(SecretLeak):
            scan("my key is " + sample_key())
        with self.assertRaises(SecretLeak):
            scan("Authorization: Bearer " + "x" * 25)
        with self.assertRaises(SecretLeak):
            scan("authorization: bearer " + "x" * 25)  # case-insensitive (finding 5)
        with self.assertRaises(SecretLeak):
            scan('{"password": "hunter2hunter2"}')  # JSON-embedded (finding 5)
        with self.assertRaises(SecretLeak):
            scan("-----BEGIN RSA PRIVATE KEY-----")

    def test_allows_normal_prose(self):
        ok, _ = scan("Review the diff in evald/repo/scoring.py and judge the verdicts.")
        self.assertTrue(ok)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.path = tmp_path()
        self.gw = Gateway(project="t", vault=Vault(vault_path=self.path, project="t"))

    def test_alpha_stripped_not_egressed(self):
        text = "Review <<alpha>>grid buy at 1% spacing<<</alpha>> and check the math."
        out, n, used, stripped, classes = self.gw.outbound(text)
        self.assertNotIn("grid buy", out)
        self.assertIn("[anon-gw: alpha withheld]", out)
        self.assertEqual(stripped, 1)
        self.assertEqual(classes, ["alpha"])

    def test_chat_body_pseudonymized_and_reidentified(self):
        body = {"messages": [{"role": "user",
                              "content": "Alex built /home/dev/evald on 10.0.0.5"}]}
        out, n, used, _, _ = self.gw.outbound_json(body)
        s = json.dumps(out)
        self.assertNotIn("Alex", s)
        self.assertNotIn("/home/dev", s)
        back = self.gw.inbound_json(out, only=used)
        self.assertEqual(
            back["messages"][0]["content"],
            "Alex built /home/dev/evald on 10.0.0.5")

    def test_chat_body_strips_alpha(self):
        body = {"messages": [{"role": "user",
                              "content": "evaluate <<results>>pnl=+4200<<</results>> for me"}]}
        out, _, _, stripped, classes = self.gw.outbound_json(body)
        self.assertNotIn("4200", json.dumps(out))
        self.assertEqual(stripped, 1)
        self.assertEqual(classes, ["results"])

    def test_reidentify_never_touches_keys(self):
        body = {"messages": [{"role": "user", "content": "Alex"}]}
        out, _, used, _, _ = self.gw.outbound_json(body)
        pseud = out["messages"][0]["content"]
        resp = {pseud: pseud}
        back = self.gw.inbound_json(resp, only=used)
        self.assertEqual(back, {pseud: "Alex"})

    def test_tool_calls_rejected(self):
        body = {"messages": [{"role": "assistant", "tool_calls":
                              [{"id": "1", "function": {"name": "f", "arguments": "{}"}}]}]}
        with self.assertRaises(ValueError):
            self.gw.outbound_json(body)

    def test_secret_in_body_blocked(self):
        body = {"messages": [{"role": "user", "content": "use " + sample_key()}]}
        with self.assertRaises(SecretLeak):
            self.gw.outbound_json(body)

    def test_policy_egress_denied(self):
        self.gw.policy.rules["providers"]["closed"] = {"egress": False}
        with self.assertRaises(PermissionError):
            self.gw.outbound("hello", provider="closed")

    def test_streaming_rejected(self):
        body = {"stream": True, "messages": [{"role": "user", "content": "hi Alex"}]}
        with self.assertRaises(ValueError):
            self.gw.outbound_json(body)


class TransportTests(unittest.TestCase):
    def test_upstream_https_required(self):
        check_upstream("https://api.openai.com")  # ok
        check_upstream("http://127.0.0.1:18110")  # loopback ok for tests
        with self.assertRaises(ValueError):
            check_upstream("http://api.example.com")


if __name__ == "__main__":
    unittest.main()
