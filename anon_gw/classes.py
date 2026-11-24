"""Content classes: proprietary information stripped before egress (default ON).

Classes are declared per project, two ways (markers take precedence):
  1. Inline markers in the packet:  <<alpha>>...<</alpha>>  (any class name)
  2. Per-project schema at ~/.config/anon-gw/classes.json:
       {"alpha": ["regex1", "regex2"], "results": ["P&L[: ].*"]}

Default policy for every class is "strip": the span is replaced with an opaque
placeholder and the original text is kept locally. A provider NEVER receives
classified content. (Cross-provider splitting was considered and cut — Alex,
2026-11-24: too complicated, not enough gain.)
"""
import json
import os
import re

MARKER = re.compile(r"<<(\w[\w-]*)>>(.*?)<</\1>>", re.DOTALL)

DEFAULT_CLASSES_PATH = os.path.expanduser("~/.config/anon-gw/classes.json")
CLASSES_ENV = "ANON_GW_CLASSES"

PLACEHOLDER = "[anon-gw: {klass} withheld]"


class Classes:
    def __init__(self, project="default", path=None):
        self.project = project
        self.path = path or os.environ.get(CLASSES_ENV) or DEFAULT_CLASSES_PATH
        self.patterns = {}  # klass -> [compiled regex]
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for klass, pats in (raw.get("projects", {}).get(self.project, {})
                            or raw.get("default", {}) or {}).items():
            self.patterns[klass] = [re.compile(p, re.DOTALL) for p in pats]

    def strip(self, text):
        """Remove classified spans. Returns (text, n_stripped, classes_seen)."""
        n = 0
        seen = set()

        def sub(m):
            nonlocal n
            n += 1
            seen.add(m.group(1))
            return PLACEHOLDER.format(klass=m.group(1))

        text = MARKER.sub(sub, text)
        for klass, pats in self.patterns.items():
            def sub2(m, _k=klass):
                nonlocal n
                n += 1
                seen.add(_k)
                return PLACEHOLDER.format(klass=_k)
            for pat in pats:
                text = pat.sub(sub2, text)
        return text, n, sorted(seen)

    def wrap(self, klass, span):
        """Helper to emit a marked span in packet templates."""
        return f"<<{klass}>>{span}<</{klass}>>"
