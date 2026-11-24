"""Policy engine: per-destination rules for what may egress."""
import json
import os

DEFAULT_POLICY = {
    "default": {"egress": True, "pseudonymize": True, "secrets": "block"},
    "providers": {},
}


class Policy:
    def __init__(self, path=None):
        self.path = path or os.path.expanduser("~/.config/anon-gw/policy.json")
        # deep copy: instance mutation must not leak into DEFAULT_POLICY or
        # other Policy instances (review finding 8)
        self.rules = json.loads(json.dumps(DEFAULT_POLICY))
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            for k, v in user.items():
                if isinstance(v, dict):
                    self.rules.setdefault(k, {}).update(v)
                else:
                    self.rules[k] = v

    def for_provider(self, provider):
        r = dict(self.rules["default"])
        r.update(self.rules.get("providers", {}).get(provider, {}))
        return r
