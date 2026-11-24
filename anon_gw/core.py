"""Core pipeline: outbound = scan secrets -> pseudonymize; inbound = re-identify."""
import json
import os
import time

from .classes import Classes
from .policy import Policy
from .secrets import scan
from .vault import Vault

# routes the API adapter is allowed to forward (review finding 2). Anything
# else is rejected rather than passed through with unhandled fields.
ALLOWED_ROUTES = {"/v1/chat/completions", "/v1/messages"}


class Gateway:
    def __init__(self, project="default", vault=None, policy=None, extra_names=(),
                 classes=None, semantic_paths=None, audit=None):
        self.vault = vault or Vault(project=project)
        self.policy = policy or Policy()
        self.project = project
        self.extra_names = list(extra_names)
        self.classes = classes or Classes(project=project)
        if semantic_paths is None:
            semantic_paths = os.environ.get("ANON_GW_SEMANTIC", "0") == "1"
        self.semantic_paths = semantic_paths
        if audit is None:
            audit = os.environ.get("ANON_GW_AUDIT", "0") == "1"
        self.audit = audit
        self.audit_path = os.path.expanduser("~/.config/anon-gw/audit.log")

    def _audit(self, provider, action, n_pseudo=0, n_stripped=0, classes=()):
        """Local-only decision log: counts and classes, NEVER payloads."""
        if not self.audit:
            return
        os.makedirs(os.path.dirname(self.audit_path), exist_ok=True)
        with open(self.audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "project": self.project, "provider": provider,
                "action": action, "n_pseudonymized": n_pseudo,
                "n_stripped": n_stripped, "classes": list(classes),
            }) + "\n")

    def _rules(self, provider):
        rules = self.policy.for_provider(provider)
        if not rules.get("egress", True):
            raise PermissionError(f"policy denies egress for {provider}")
        return rules

    def _strip_classes(self, text):
        """Strip classified content (default ON for every provider)."""
        return self.classes.strip(text)

    def outbound(self, text, provider="default"):
        """Prepare a packet for egress. Raises SecretLeak on credentials.
        Returns (text, n_subs, used_pseudonyms, n_stripped, classes)."""
        rules = self._rules(provider)
        scan(text)  # fail closed on credentials
        text, n_stripped, stripped_classes = self._strip_classes(text)
        if rules.get("pseudonymize", True):
            text, n, used = self.vault.pseudonymize(
                text, extra_names=self.extra_names, semantic_paths=self.semantic_paths)
            self._audit(provider, "outbound", n, n_stripped, stripped_classes)
            return text, n, used, n_stripped, stripped_classes
        self._audit(provider, "outbound-nopseudo", 0, n_stripped, stripped_classes)
        return text, 0, [], n_stripped, stripped_classes

    def inbound(self, text, only=None):
        """Re-identify an inbound response."""
        return self.vault.reidentify(text, only=only)

    def _transform_text(self, t):
        """strip classes + pseudonymize one text unit. Returns (t2, k, u, s, cls)."""
        t2, s, cls = self._strip_classes(t)
        t2, k, u = self.vault.pseudonymize(
            t2, extra_names=self.extra_names, semantic_paths=self.semantic_paths)
        return t2, k, u, s, cls

    @staticmethod
    def _anthropic_texts(body):
        """Yield (container, key) for every text field of a /v1/messages body."""
        sysf = body.get("system")
        if isinstance(sysf, str):
            yield sysf, ("system",)
        elif isinstance(sysf, list):
            for i, blk in enumerate(sysf):
                if isinstance(blk, dict) and blk.get("type") == "text":
                    yield blk["text"], ("system", i)
        for mi, msg in enumerate(body.get("messages", [])):
            if msg.get("tool_calls") or msg.get("function_call") or msg.get("name") \
                    or msg.get("tool_use") or msg.get("tool_result"):
                raise ValueError("unsupported fields in message (tool content); "
                                 "anon-gw only forwards plain chat content")
            c = msg.get("content")
            if isinstance(c, str):
                yield c, (mi, "content")
            elif isinstance(c, list):
                for bi, blk in enumerate(c):
                    if isinstance(blk, dict) and blk.get("type") == "text":
                        yield blk["text"], (mi, bi)

    def outbound_anthropic(self, body, provider="default"):
        """Scan + strip classes + pseudonymize an Anthropic /v1/messages body.
        Returns (body, n, used, n_stripped, classes)."""
        rules = self._rules(provider)
        scan(json.dumps(body))
        body = json.loads(json.dumps(body))
        if body.get("stream"):
            raise ValueError("streaming requests are not supported yet")
        n, used, n_stripped, stripped_classes = 0, [], 0, []
        for text, loc in list(self._anthropic_texts(body)):
            t2, k, u, s, cls = self._transform_text(text)
            if loc == ("system",):
                body["system"] = t2
            elif len(loc) == 2 and loc[0] == "system":
                body["system"][loc[1]]["text"] = t2
            elif loc[1] == "content":
                body["messages"][loc[0]]["content"] = t2
            else:  # (mi, block_index)
                body["messages"][loc[0]]["content"][loc[1]]["text"] = t2
            n += k
            used += u
            n_stripped += s
            stripped_classes += cls
        self._audit(provider, "outbound-anthropic", n, n_stripped,
                    sorted(set(stripped_classes)))
        return body, n, used, n_stripped, sorted(set(stripped_classes))

    def outbound_json(self, body, provider="default"):
        """Scan + strip classes + pseudonymize a chat-completions body.
        Returns (body, n, used, n_stripped, classes)."""
        rules = self._rules(provider)
        scan(json.dumps(body))
        body = json.loads(json.dumps(body))
        if body.get("stream"):
            raise ValueError("streaming requests are not supported yet")
        n_stripped, stripped_classes = 0, []
        if rules.get("pseudonymize", True):
            n, used = 0, []
            for msg in body.get("messages", []):
                # review finding 2: tool arguments, function calls and 'name' can
                # carry identifying data we don't handle — reject rather than leak.
                if msg.get("tool_calls") or msg.get("function_call") or msg.get("name"):
                    raise ValueError("unsupported fields in message (tool_calls/function_call/name); "
                                     "anon-gw only forwards plain chat content")
                c = msg.get("content")
                if isinstance(c, str):
                    c2, s, cls = self._strip_classes(c)
                    c2, k, u = self.vault.pseudonymize(
                        c2, extra_names=self.extra_names, semantic_paths=self.semantic_paths)
                    msg["content"] = c2
                    n_stripped += s
                    stripped_classes += cls
                    n += k
                    used += u
                elif isinstance(c, list):
                    for part in c:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            t2, s, cls = self._strip_classes(part["text"])
                            t2, k, u = self.vault.pseudonymize(
                                t2, extra_names=self.extra_names,
                                semantic_paths=self.semantic_paths)
                            part["text"] = t2
                            n_stripped += s
                            stripped_classes += cls
                            n += k
                            used += u
            self._audit(provider, "outbound-json", n, n_stripped,
                        sorted(set(stripped_classes)))
            return body, n, used, n_stripped, sorted(set(stripped_classes))
        return body, 0, [], n_stripped, stripped_classes

    def inbound_json(self, body, only=None):
        """Re-identify an inbound parsed response, restoring only decoded string
        VALUES (never keys or serialized syntax), so JSON stays valid and
        protocol fields are untouched (review finding 7)."""
        def restore(o):
            if isinstance(o, dict):
                return {k: restore(v) for k, v in o.items()}
            if isinstance(o, list):
                return [restore(v) for v in o]
            if isinstance(o, str):
                return self.vault.reidentify(o, only=only)
            return o
        return restore(body)
