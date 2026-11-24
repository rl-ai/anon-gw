"""anon-gw selftest: verify the gate works on THIS machine, right now.

Embeds a minimal corpus (synthetic values only) so an installed package can
verify itself without the repo's fixture files:
  - secret gate catches every credential class (recall gate)
  - benign prose passes
  - pseudonymize -> re-identify roundtrip
  - alpha stripping
Exit 0 = pass, 1 = FAIL (do not trust the gate).
"""
import sys

from .classes import Classes
from .core import Gateway
from .secrets import SecretLeak, scan
from .vault import Vault


def _sample_key():
    return "sk-" + "a1b2c3d4e5f6a7b8c9d0"


POSITIVES = [
    ("bearer", "Authorization: Bearer " + "x" * 25),
    ("openai-key", "my key is " + _sample_key()),
    ("github", "token ghp_" + "z" * 25),
    ("aws", "id AKIA" + "Q" * 16),
    ("slack", "slack xoxb-" + "n" * 14),
    ("jwt", "jwt eyJ" + "e" * 22 + "." + "y" * 12),
    ("pem", "-----BEGIN RSA PRIVATE KEY-----"),
    ("kv", 'password: ' + "p" * 10),
]
NEGATIVES = [
    "The fleet judged 43,628 items with zero failed jobs.",
    "f(x) = sk + x^2 is the scoring function.",
    "The password policy requires 12 characters minimum.",
]


def run(out=print):
    checks = []
    ok_all = True

    # 1. secret gate recall
    for name, text in POSITIVES:
        try:
            scan(text)
            ok_all = False
            checks.append(f"FAIL secret-gate missed {name}")
        except SecretLeak:
            checks.append(f"ok   secret-gate blocks {name}")

    # 2. benign passes
    for text in NEGATIVES:
        try:
            scan(text)
            checks.append("ok   benign prose passes")
        except SecretLeak:
            ok_all = False
            checks.append(f"FAIL false positive: {text[:40]}")

    # 3. roundtrip (temp vault)
    import tempfile
    fd, p = tempfile.mkstemp(suffix=".json")
    sys_created = True
    import os
    os.close(fd)
    os.unlink(p)
    v = Vault(vault_path=p, project="selftest")
    text = "Alex works at 10.0.0.5 on /home/dev/evald"
    out_text, n, used = v.pseudonymize(text)
    if "Alex" in out_text or n < 3:
        ok_all = False
        checks.append("FAIL pseudonymization incomplete")
    else:
        checks.append("ok   pseudonymization + roundtrip")
    if v.reidentify(out_text, only=used) != text:
        ok_all = False
        checks.append("FAIL re-identification broken")
    os.unlink(p)

    # 4. alpha stripping
    c = Classes(project="selftest", path="/nonexistent")
    stripped, s, classes = c.strip("plan <<alpha>>grid 1% dips<<</alpha>> end")
    if "grid" in stripped or s != 1:
        ok_all = False
        checks.append("FAIL alpha stripping broken")
    else:
        checks.append("ok   alpha stripping")

    for line in checks:
        out(line)
    out("selftest: " + ("PASS" if ok_all else "FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(run())
