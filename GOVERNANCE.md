# Governance: listen and curate

anon-gw is developed here as the canonical version **for our use**. External
improvements — forks, derived tools, borrowed components — are handled by
listening and curation, not by mandatory flow-back (Alex, 2026-11-24: forced
upstreaming is unrealistic; people will fork and improve on their own terms).

## The curation loop

1. **Listen** — watch the ecosystem: GitHub issues/PRs on the published repo,
   notable forks, blog posts and tooling that build on anon-gw. This is the
   same OSS-listening pipeline Aerial runs for related projects; anon-gw joins
   that rotation once published.
2. **Curate** — evaluate surfaced improvements for fit: does it improve
   privacy guarantees, reduce false blocks, or reduce friction? Security
   fixes always qualify; breaking vault-format changes get a migration path
   or are ported as a versioned upgrade.
3. **Port** — land curated improvements here with tests, credit the source.
   No obligation on anyone to contribute back; we take what's good.

## What we commit to

- Keep this repo the version WE run (our cloud lanes depend on it).
- Vault-format compatibility: our own changes to the vault or pseudonym
  scheme migrate existing vaults, never silently break them.
- Publicize curated improvements so the ecosystem sees we're a good citizen —
  that's what makes the listening loop actually receive signal.
