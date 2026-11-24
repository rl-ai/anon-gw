# Security policy

## Reporting

Email security@ (see repository contact) or open a GitHub security advisory.
Do NOT open a public issue for a vulnerability.

## Scope

- `anon_gw/vault.py` — pseudonymization and re-identification correctness
- `anon_gw/secrets.py` — credential detection
- `anon_gw/server.py` — the local API proxy (auth, routing, body handling)
- `anon_gw/transport.py` — network-path enforcement
- `anon_gw/cli.py` — CLI adapter

## Hardening commitments

- Fail closed: any pipeline error blocks egress rather than passing through.
- No prompts, credentials, or vault contents are ever logged.
- The vault is local-only; no code path uploads it.

## Response

Vulnerabilities are triaged within 72 hours and fixed releases are cut for
anything that could leak credentials or the vault.
