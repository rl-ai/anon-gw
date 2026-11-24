# anon-gw

**Local anonymization gateway for cloud model subscriptions and APIs.**

You paste a stack trace into an AI tool. Now the provider has your username,
hostname, file paths, and IP address — stored on their servers, possibly
training their next model. anon-gw sits between your AI tools and the cloud
and rewrites that story before it leaves your machine.

> **A VPN changes the network path. anon-gw changes the payload.** They compose.

It covers all cloud AI traffic — CLI agents (Claude Code, Codex) and raw API
calls — through one local gate that guarantees:

1. **Content pseudonymization** — person names, hostnames, paths, IPs, emails
   are replaced with stable per-project pseudonyms before egress; responses
   are re-identified on return. The vault never leaves the machine.
2. **Alpha stripping** — proprietary content (strategy parameters, results,
   customer data) marked `<<alpha>>...<</alpha>>` or matched by your project's
   class schema is **removed before egress** and replaced with an opaque
   placeholder. The provider never sees it; the original stays local.
3. **Secret gate** — API keys, bearer tokens, GitHub/AWS/Slack credentials,
   JWTs and private-key blocks are **blocked at the gate** (fail closed),
   never proxied.
4. **IP privacy** — egress through a pluggable transport (direct for dev,
   SOCKS5/Tor for anonymity). Your home IP never touches cloud endpoints.
5. **Policy engine** — per-destination egress rules.

## Honest limitation

This is defense-in-depth, not absolute anonymity: distinctive content may still
fingerprint identity. The promise is systematic protection (IP + secrets +
pseudonyms + policy), not magic.

## Usage

```sh
anon-gw setup        # one command: config dir, vault, classes template, usage hints
anon-gw selftest     # verify the gate works on this machine (exit 1 = do not trust)
```

**Base-URL mode (recommended: zero workflow change)** — point your AI tool at
the gateway; it natively supports both dialects:

```sh
anon-gw serve --upstream https://api.anthropic.com --port 8070
export ANTHROPIC_BASE_URL=http://127.0.0.1:8070     # Claude Code / Cursor / SDKs
# or OPENAI_BASE_URL / OPENAI_API_BASE equivalents for OpenAI-dialect tools
```

**CLI adapter** — wrap any packet flow:

```sh
anon-gw enc < packet.txt > packet.anon.txt   # scan + pseudonymize + strip (exit 3 = blocked secret)
anon-gw preview < packet.txt                 # dry-run: see exactly what would leave
anon-gw dec < reply.txt > reply.clean.txt    # re-identify
```

**Optional behavior**

```sh
ANON_GW_PROJECT=myproject      # pseudonym scope (per-project salts)
ANON_GW_NAMES="Your Name"      # explicit names to pseudonymize
ANON_GW_SEMANTIC=1             # paths -> /home/user/... (valid paths, still reversible)
ANON_GW_AUDIT=1                # local decision log: counts + classes, never payloads
ANON_GW_TRANSPORT=direct       # or an http(s) proxy URL for egress
```

Integrations live in `ai-ops/bin/cloud_call.sh` (on by default; `ANON_GW_DISABLE=1`
bypasses).

## Status

v0.2.2: core pipeline + vault + secret gate + alpha stripping + policy + API
proxy (OpenAI + Anthropic dialects, base-URL mode) + CLI, 36 tests, live e2e
verified. Outbound data policy: OUTBOUND_POLICY.md (all egress gated unless
inclusion is intentional).
Roadmap (deferred by design): streaming support, SQLite vault, transparent TLS
proxying, external security audit.
Five-minute skeptic test: `sh examples/demo.sh`.

## Development

```sh
python -m unittest discover -s tests
```
