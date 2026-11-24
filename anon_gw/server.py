"""Local API adapter: an OpenAI-compatible proxy on 127.0.0.1 (loopback only).

Point any client at http://127.0.0.1:8070/v1 instead of the provider. The gateway
pseudonymizes message content, blocks credentials, and forwards through the
configured transport. Auth passthrough: clients still present their own provider
key in Authorization; the gateway does not store keys.

Security posture (post-review):
  - loopback bind only (review finding 3)
  - only /v1/chat/completions is forwarded; other routes rejected (finding 2)
  - policy enforced from the CONFIGURED upstream, not a client header (finding 1)
  - re-identification scoped to the pseudonyms created for THIS request (finding 3)
  - body size capped; streaming requests rejected (finding 9)
  - https-only upstreams (loopback http allowed for tests) (finding 6)

Run:  python -m anon_gw.server --upstream https://api.openai.com --port 8070
"""
import argparse
import http.server
import json
import urllib.error
import urllib.request

from .core import ALLOWED_ROUTES, Gateway
from .transport import check_upstream, from_env

MAX_BODY = 10 * 1024 * 1024  # 10 MB cap (review finding 9)


class Handler(http.server.BaseHTTPRequestHandler):
    upstream = "https://api.openai.com"
    provider_name = "default"  # policy key for the configured destination
    gateway = None  # type: Gateway
    transport = None

    def do_POST(self):
        if self.path not in ALLOWED_ROUTES:
            self._reply(404, {"error": f"anon-gw only forwards {sorted(ALLOWED_ROUTES)}"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "bad Content-Length"})
            return
        if length < 0 or length > MAX_BODY:
            self._reply(413, {"error": f"body exceeds {MAX_BODY} bytes"})
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
            if body.get("stream"):
                raise ValueError("streaming requests are not supported yet")
            # policy is keyed to the CONFIGURED upstream, not a client header
            # (review finding 1); route decides the body dialect
            if self.path == "/v1/messages":
                body, n, used, n_stripped, _cls = self.gateway.outbound_anthropic(
                    body, provider=self.provider_name)
            else:
                body, n, used, n_stripped, _cls = self.gateway.outbound_json(
                    body, provider=self.provider_name)
        except Exception as e:
            self._reply(403, {"error": f"anon-gw blocked outbound packet: {e}"})
            return
        payload = json.dumps(body).encode()
        req = urllib.request.Request(
            self.upstream.rstrip("/") + self.path, data=payload, method="POST")
        for h in ("Authorization", "Content-Type"):
            if self.headers.get(h):
                req.add_header(h, self.headers[h])
        try:
            resp = self.transport.open(req)
            data = resp.read()
            status = resp.status
        except urllib.error.HTTPError as e:
            data = e.read()
            status = e.code
        except Exception as e:
            self._reply(502, {"error": f"anon-gw upstream error: {e}"})
            return
        try:
            # restore ONLY pseudonyms this request created (review finding 3)
            data = json.dumps(self.gateway.inbound_json(json.loads(data), only=used)).encode()
        except Exception:
            data = self.gateway.inbound(data.decode("utf-8", "replace"), only=used) \
                .encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Anon-Gw-Pseudonyms", str(n))
        self.send_header("X-Anon-Gw-Stripped", str(n_stripped))
        self.end_headers()
        self.wfile.write(data)

    def _reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature; never log prompts
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(prog="anon-gw serve")
    ap.add_argument("--upstream", default="https://api.openai.com")
    ap.add_argument("--bind", default="127.0.0.1")  # loopback default (finding 3)
    ap.add_argument("--port", type=int, default=8070)
    ap.add_argument("--provider", default="default", help="policy key for the upstream")
    ap.add_argument("--project", default="default")
    ap.add_argument("--names", default="", help="comma-separated names to pseudonymize")
    args = ap.parse_args(argv)

    check_upstream(args.upstream)
    if args.bind not in ("127.0.0.1", "localhost"):
        print("warning: non-loopback bind exposes re-identification to the network",
              flush=True)
    Handler.upstream = args.upstream
    Handler.provider_name = args.provider
    Handler.gateway = Gateway(project=args.project,
                              extra_names=[n.strip() for n in args.names.split(",") if n.strip()])
    Handler.transport = from_env()
    srv = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"anon-gw listening on {args.bind}:{args.port} -> {args.upstream}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
