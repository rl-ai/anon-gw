"""anon-gw CLI: packet encrypt-style encode/decode for CLI adapters.

  anon-gw enc < in.txt > out.txt    # scan secrets + pseudonymize (outbound)
  anon-gw dec < in.txt > out.txt    # re-identify (inbound)
  anon-gw serve --upstream URL --port N   # API adapter (OpenAI-compatible proxy)

Project comes from ANON_GW_PROJECT (default: hostname of the working context).
"""
import json
import os
import sys

from .core import Gateway
from .secrets import SecretLeak
from .vault import Vault


def _gw():
    return Gateway(project=os.environ.get("ANON_GW_PROJECT", "default"),
                   extra_names=[n.strip() for n in
                                os.environ.get("ANON_GW_NAMES", "").split(",") if n.strip()])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "serve":
        from .server import main as serve
        return serve(sys.argv[2:]) or 0
    if cmd == "selftest":
        from .selftest import run
        return run()
    if cmd == "setup":
        base = os.path.expanduser("~/.config/anon-gw")
        os.makedirs(base, exist_ok=True)
        os.chmod(base, 0o700)
        Vault(project=os.environ.get("ANON_GW_PROJECT", "default"))  # creates vault
        cls_path = os.path.join(base, "classes.json")
        if not os.path.exists(cls_path):
            with open(cls_path, "w") as fh:
                json.dump({"default": {}, "projects": {}}, fh, indent=2)
        print(f"anon-gw setup complete: {base}/")
        print("  vault.json          identity pseudonyms (never egresses)")
        print("  classes.json        declare proprietary content patterns")
        print("one-command usage:")
        print("  # point AI tools at the gateway (base-URL mode):")
        print("  anon-gw serve --upstream https://api.anthropic.com --port 8070")
        print("  export ANTHROPIC_BASE_URL=http://127.0.0.1:8070")
        print("  # or wrap packets (CLI mode):")
        print("  anon-gw enc < packet.txt > packet.anon.txt")
        print("verify with: anon-gw selftest")
        return 0
    text = sys.stdin.read()
    gw = _gw()
    if cmd == "enc":
        try:
            out, n, _used, n_stripped, classes = gw.outbound(text)
        except SecretLeak as e:
            print(f"anon-gw: {e}", file=sys.stderr)
            return 3
        print(f"anon-gw: pseudonymized {n} entities, stripped {n_stripped} "
              f"classified spans ({', '.join(classes) or 'none'})", file=sys.stderr)
        sys.stdout.write(out)
    elif cmd == "preview":
        # v0.2.1: dry-run through the PRODUCTION pipeline (same outbound path,
        # nothing sent, nothing echoed that would leak a credential)
        try:
            out, n, used, n_stripped, classes = gw.outbound(text)
        except SecretLeak as e:
            print(f"BLOCKED: {e}", file=sys.stderr)
            return 3
        print("== would leave the machine ==")
        print(out)
        print(f"== report: {n} entities pseudonymized, {n_stripped} classified "
              f"spans withheld ({', '.join(classes) or 'none'}) ==")
        print("== nothing was sent; this ran the exact production pipeline ==", file=sys.stderr)
    elif cmd == "dec":
        sys.stdout.write(gw.inbound(text))
    else:
        print(f"unknown command {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
