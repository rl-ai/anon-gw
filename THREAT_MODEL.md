# Threat model

## What anon-gw protects

| Asset | Threat | Protection |
|---|---|---|
| Your IP address | Cloud provider or network observer links requests to your home IP | Egress transport (direct only by explicit choice; proxy/Tor for real anonymity) |
| Credentials | API keys, bearer tokens, private keys leave in a packet | Secret gate: fail-closed blocking before egress |
| Identity in content | Names, hostnames, IPs, paths, emails identify you to the model provider | Pseudonym vault: stable per-project pseudonyms, reversible only locally |
| Vault | Theft/corruption exposes the identity map | 0600 file, 0700 dir, permission validation, atomic writes, cross-process locking |

## What anon-gw does NOT protect (be honest)

1. **Content fingerprinting.** Distinctive details (writing style, project
   specifics, code structure) can identify you even with names replaced.
   Pseudonymization is systematic, not semantic. Do not paste material whose
   *content itself* identifies you if that matters.
2. **Provider-side account identity.** If you authenticate with your own API
   key or subscription, the provider knows the account regardless of transport.
   IP privacy and account privacy are separate axes.
3. **Malicious local processes.** Anything running as your user can read the
   vault. The threat model assumes your machine is not compromised.
4. **Regex miss.** The secret gate and entity detection are pattern-based.
   Unfamiliar credential formats can slip through; false positives can block
   benign text. `anon-gw enc` reports what it substituted — review it for
   high-stakes packets.
5. **TLS to the provider.** The gateway terminates nothing for the CLI
   adapter (packets are transformed before the CLI sends them), but the API
   adapter forwards TLS via urllib — certificate verification is standard
   library behavior, not pinned.

## Trust assumptions

- The local machine and the vault are trusted.
- The pseudonymization salt is random per project and never leaves the machine.
- Providers are honest but curious: they see pseudonymized content and will
  store it per their policy.
