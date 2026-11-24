"""Mock upstream for the five-minute skeptic test.

Records exactly what it receives (so you can SEE what a provider would see)
and replies as a chat model echoing that payload back — which exercises the
re-identification path too.

Run:  python examples/mock_upstream.py --port 9099 --log /tmp/mock-received.json
"""
import argparse
import http.server
import json


class Handler(http.server.BaseHTTPRequestHandler):
    log_path = "/tmp/mock-received.json"

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(raw.decode("utf-8", "replace") + "\n")
        body = json.loads(raw)
        seen = " | ".join(m.get("content", "") for m in body.get("messages", [])
                          if isinstance(m.get("content"), str))
        reply = {"id": "mock-1", "object": "chat.completion", "status": 200,
                 "choices": [{"message": {"role": "assistant",
                                          "content": "I received exactly: " + seen}}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9099)
    ap.add_argument("--log", default="/tmp/mock-received.json")
    args = ap.parse_args()
    Handler.log_path = args.log
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"mock upstream on 127.0.0.1:{args.port}, logging to {args.log}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
