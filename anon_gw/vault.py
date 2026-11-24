"""Pseudonym vault: deterministic, reversible, per-project pseudonyms.

Pseudonyms are derived via HMAC-SHA256(project_salt, value) so they are:
  - stable within a project (the model sees consistent entities across packets)
  - rotated when the project salt rotates (B3 policy)
  - irreversible without the local vault file

The vault file (~/.config/anon-gw/vault.json) holds per-project salts and the
reverse map built as values are pseudonymized. It is chmod 600. It NEVER egresses.
"""
import fcntl
import hashlib
import hmac
import json
import os
import re
import threading

VAULT_ENV = "ANON_GW_VAULT"
DEFAULT_VAULT = os.path.expanduser("~/.config/anon-gw/vault.json")

# entity classes and their detection. Order matters: most-specific first
# (email beats path beats person) — combined with overlap resolution below.
PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "path": re.compile(r"/home/[a-z][a-z0-9_-]{1,20}(?:/[A-Za-z0-9._-]+)*"),
    "person": re.compile(
        r"\b(?:Alex|ray)\b(?=[ ,.'\":;)]|$)"),  # extendable; real name list loaded from config
    "hostname": re.compile(r"\b[a-z][a-z0-9-]{2,20}\.(?:local|lan|home\.arpa)\b", re.I),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


class Vault:
    def __init__(self, vault_path=None, project="default"):
        self.path = vault_path or os.environ.get(VAULT_ENV) or DEFAULT_VAULT
        self.project = project
        self._lock = threading.Lock()  # in-process serialization (review finding 4)
        self._load()

    def _load(self):
        self.data = {"salts": {}, "reverse": {}}
        if os.path.exists(self.path):
            st = os.stat(self.path)
            if st.st_mode & 0o077:  # review finding 4: validate permissions
                raise PermissionError(f"vault {self.path} must not be group/other-readable")
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        self.data.setdefault("salts", {})
        self.data.setdefault("reverse", {})
        d = os.path.dirname(self.path)
        created = not os.path.exists(d)
        os.makedirs(d, exist_ok=True)
        if created:
            os.chmod(d, 0o700)

    def salt(self, project=None):
        with self._lock:
            return self._salt(project or self.project)

    def _salt(self, project):
        if project not in self.data["salts"]:
            self.data["salts"][project] = os.urandom(32).hex()
            self._save_locked()
        return self.data["salts"][project]

    def rotate(self, project=None):
        """Rotate a project's salt: all its pseudonyms change on next pass."""
        with self._lock:
            self.data["salts"][project or self.project] = os.urandom(32).hex()
            self._save_locked()

    def pseudonym(self, value, klass="id"):
        with self._lock:
            salt = self._salt(self.project)
        digest = hmac.new(salt.encode(), (klass + ":" + value).encode(), hashlib.sha256).hexdigest()[:12]
        return f"{klass}-{digest}"

    def _save_locked(self):
        # cross-process serialization + atomic tmp created 0600 (review finding 4)
        d = os.path.dirname(self.path)
        os.makedirs(d, exist_ok=True)
        lockfile = os.path.join(d, os.path.basename(self.path) + ".lock")
        with open(lockfile, "a") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            if os.path.exists(self.path):  # merge, never clobber newer data
                with open(self.path, "r", encoding="utf-8") as fh:
                    fresh = json.load(fh)
                fresh.setdefault("salts", {})
                fresh.setdefault("reverse", {})
                for proj, s in fresh["salts"].items():
                    self.data["salts"].setdefault(proj, s)
                for proj, m in fresh["reverse"].items():
                    self.data["reverse"].setdefault(proj, {}).update(m)
            fd = os.open(self.path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=1)
            os.replace(self.path + ".tmp", self.path)
            fcntl.flock(lf, fcntl.LOCK_UN)

    def register_reverse(self, pseudonym, original):
        with self._lock:
            self.data["reverse"].setdefault(self.project, {})[pseudonym] = original
            self._save_locked()

    def reidentify(self, text, project=None, only=None):
        """Restore original values in an inbound packet.

        only: an iterable of pseudonyms created for THIS exchange. When given
        (server path), restoration is scoped to them — a response cannot be used
        to mine the vault's full history (review finding 3). None restores
        project-wide (CLI path, local-only use).
        """
        project = project or self.project
        rev = self.data["reverse"].get(project, {})
        if only is not None:
            rev = {p: rev[p] for p in only if p in rev}
        for pseud, orig in sorted(rev.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(pseud, orig)
        return text

    def pseudonymize(self, text, extra_names=(), semantic_paths=False):
        """Replace known identifiers in an outbound packet.

        Single pass over the ORIGINAL input with overlap resolution
        (longest match wins) so matches can't shadow each other or leak
        fragments (review finding 10).
        semantic_paths: replace /home/<user>/... with /home/user/... (a valid,
        runnable path) instead of an opaque pseudonym; re-identification still
        works via the reverse map. (Claude-review insight: opaque path
        pseudonyms break code the model writes back.)
        Returns (text, n_subs, used_pseudonyms).
        """
        matches = []  # (start, end, value, klass, replacement_or_None)
        for name in extra_names:
            if not name:
                continue
            pseud = self.pseudonym(name, "person")
            start = 0
            while True:
                i = text.find(name, start)
                if i < 0:
                    break
                matches.append((i, i + len(name), name, "person", pseud))
                start = i + len(name)
        for klass, pat in PATTERNS.items():
            for m in pat.finditer(text):
                repl = None
                if semantic_paths and klass == "path":
                    repl = re.sub(r"^(/home/)[^/]+", r"\1user", m.group(0))
                matches.append((m.start(), m.end(), m.group(0), klass, repl))
        matches.sort(key=lambda t: (-(t[1] - t[0]), t[0]))
        chosen, taken = [], []
        for s, e, v, k, p in matches:
            if any(s < te and ts < e for ts, te in taken):
                continue
            chosen.append((s, e, v, k, p))
            taken.append((s, e))
        chosen.sort()
        used = []
        out, last = [], 0
        for s, e, v, k, repl in chosen:
            if repl is None:
                repl = self.pseudonym(v, k)
            self.register_reverse(repl, v)
            used.append(repl)
            out.append(text[last:s])
            out.append(repl)
            last = e
        out.append(text[last:])
        return "".join(out), len(chosen), used
