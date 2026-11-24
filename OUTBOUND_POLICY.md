# Outbound data policy

**Standing rule (Ray, 2026-11-24): everything that leaves this project —
publishing, packets to cloud models, releases, examples, docs — goes through
anon-gw (or an equivalent gate) unless sensitive data is included
intentionally, and then the inclusion is explicit and documented.**

Concretely:

1. **Cloud model packets** — always through the gateway (CLI `enc` or the API
   proxy). This is already the default in our dispatch scripts.
2. **Publishing a release or the repo itself** — `pii_scan` must be clean
   first; anything intentional (e.g. a redacted-but-real example) is listed in
   the release notes with a reason.
3. **Examples and docs** — use generic fixtures only (`dev`, `/home/dev`,
   `Alex`, `10.0.0.5`). No internal identifiers, ever.
4. **History hygiene** — a public repo's git history is outbound data too:
   before publishing, either squash to a clean initial commit or scrub
   history; real identifiers in old commits count as leaks.
5. **Intentional inclusion** — if a packet must contain sensitive data (e.g.
   we deliberately share a real config with a provider for debugging), that
   is a decision, stated at send time, never a default.
