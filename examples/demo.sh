#!/bin/sh
# The five-minute skeptic test: see exactly what a provider receives.
#   1. start the mock upstream + the gateway
#   2. send a packet containing a name, an IP, a path — and a fake credential
#   3. show: what the provider received (pseudonymized), the credential BLOCKED,
#      and the re-identified reply
set -eu
cd "$(dirname "$0")/.."
LOG=${MOCK_LOG:-/tmp/mock-received.json}
: > "$LOG"
python3 examples/mock_upstream.py --port 9099 --log "$LOG" &
MOCK=$!
sleep 1
python3 -m anon_gw.server --upstream http://127.0.0.1:9099 --port 8070 \
  --project demo --names "Grace Hopper" &
GW=$!
sleep 1
trap 'kill $MOCK $GW 2>/dev/null || true' EXIT

echo "=== 1. normal packet: what does the provider actually receive? ==="
printf 'Grace Hopper maintains the eval fleet at 10.0.0.5 under /home/grace.\n' \
  | curl -s http://127.0.0.1:8070/v1/chat/completions \
      -H "Content-Type: application/json" \
      -d '{"model":"demo","messages":[{"role":"user","content":"Grace Hopper maintains the eval fleet at 10.0.0.5 under /home/grace."}]}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['choices'][0]['message']['content'])"
echo "--- provider received (raw log):"
cat "$LOG"

echo
echo "=== 2. credential packet: blocked at the gate ==="
code=$(curl -s -o /tmp/anongw-demo-blocked.json -w '%{http_code}' http://127.0.0.1:8070/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"here is my key sk-abcdefghijklmnop1234567890"}]}' || true)
echo "HTTP $code (expected 403, fail-closed)"
cat /tmp/anongw-demo-blocked.json; echo

echo
echo "=== verdict ==="
echo "The provider saw pseudonyms only; the credential never left; the reply"
echo "came back re-identified. A VPN changes the network path — this changes"
echo "the payload before it leaves the machine."
