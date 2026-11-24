"""Secret gate: block credentials from egress. Fail closed."""
import re

SECRET_PATTERNS = [
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "openai-style key"),
    (re.compile(r"\bbearer\s+[A-Za-z0-9._-]{25,}\b", re.I), "bearer token"),
    (re.compile(r'"?(?:api[_-]?key|apikey|token|secret|password)"?\s*[:=]\s*"?[^"\s,}]{8,}', re.I),
     "key-value credential"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "github token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws access key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
]

HUB_BEARER_HINT = re.compile(r"[A-Za-z0-9]{40,}")


class SecretLeak(Exception):
    def __init__(self, kind, sample):
        super().__init__(f"blocked egress: {kind} (sample withheld)")
        self.kind = kind


def scan(text):
    """Raise SecretLeak on any credential pattern. Return (ok, kinds)."""
    kinds = []
    for pat, kind in SECRET_PATTERNS:
        if pat.search(text):
            kinds.append(kind)
    if kinds:
        raise SecretLeak(kinds[0], "")
    return True, kinds
