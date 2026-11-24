# Install

## Requirements

Python 3.10+ (stdlib only — no dependencies).

## From source

```sh
git clone <repo-url> anon-gw && cd anon-gw
pip install -e .          # provides the `anon-gw` command
python -m unittest discover -s tests   # 16 tests should pass
```

## Configure

```sh
export ANON_GW_PROJECT=myproject      # pseudonym scope (per-project salts)
export ANON_GW_NAMES="Your Name"      # names to pseudonymize
export ANON_GW_TRANSPORT=direct       # or an http(s) proxy URL for egress
```

The vault lives at `~/.config/anon-gw/vault.json` (created on first use,
chmod 600, never uploaded).

## Use

**CLI adapter** — wrap any packet flow:

```sh
anon-gw enc < packet.txt > packet.anon.txt   # scan + pseudonymize (exit 3 = blocked secret)
anon-gw dec < reply.txt > reply.clean.txt    # re-identify
```

**API adapter** — local OpenAI-compatible proxy:

```sh
anon-gw serve --upstream https://api.openai.com --port 8070
# point clients at http://127.0.0.1:8070/v1
```

## Verify in five minutes

```sh
sh examples/demo.sh
```

Shows exactly what a provider receives (pseudonyms), a credential blocked at
the gate, and the re-identified reply. See THREAT_MODEL.md for what this does
and does not protect.
