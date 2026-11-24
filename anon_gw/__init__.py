"""anon-gw: local anonymization gateway for cloud model subscriptions and APIs.

Privacy architecture (defense-in-depth, honestly documented):
  1. IP layer: egress through a pluggable transport (direct | socks5 | tor | vps-relay).
     Your home IP never touches cloud endpoints.
  2. Content layer: pseudonymization vault — person names, hostnames, project paths,
     IPs, and other identifiers are replaced with stable per-project pseudonyms
     before egress; responses are re-identified on return. The vault never leaves
     the machine.
  3. Secret layer: credential scanning — anything that looks like a key, bearer
     token, or private credential is BLOCKED at the gate, never proxied.
  4. Policy layer: per-destination rules for what may egress.

This is NOT absolute anonymity: a determined analyst may still infer identity from
distinctive content. The product promise is systematic defense, not magic.
"""
__version__ = "0.1.0"
