# Threat model

## Assets

- the user's ability to authorize a signature;
- persona separation and privacy;
- private signing keys and wallet-held credentials;
- the exact bytes and human-readable intent being signed;
- trust policies, key history, and revocation history;
- verifier accuracy and understandable failure reporting.

## Adversaries

- a malicious or compromised Omarchy plugin;
- a hostile file, archive, proof bundle, website, or media object;
- a publisher whose key is valid but whose software is malicious;
- a compromised signing key or CI workflow;
- a verifier tricked by stale, ambiguous, or substituted content;
- a service trying to correlate otherwise separate personas;
- malware operating as the same desktop user.

## Required properties

- Signing requires an unambiguous statement, selected persona, artifact digest,
  and explicit consent in a process outside the caller's UI surface.
- Verification is offline-capable and never executes the signed artifact.
- Parsers have size limits and reject unknown critical fields.
- Displayed labels, actors, policies, and notes reject control and bidirectional
  formatting characters that could visually reorder security evidence.
- A proof is bound to a domain-separated purpose and exact statement bytes.
- Key identity, legal identity, build provenance, review, and safety are shown as
  distinct facts or unknowns.
- Revocation never rewrites history: the report shows who revoked what, when,
  and under which policy, while saying the credential is no longer valid.
- Export excludes private material unless the user explicitly performs a
  supported, secure key-backup operation.

## Known limitations of the first slice

- The CLI invokes fixed `/usr/bin/ssh-keygen` on Unix after rejecting symlinks,
  untrusted owners, and group/world-writable files. It clears the subprocess
  environment and restores only a small session/agent allowlist. Correctness of
  the accepted executable remains inherited from the operating system.
- The Omarchy adapter invokes fixed `/usr/bin/omarchy-plugin-validate` and
  `/usr/bin/omarchy-shell` paths and rejects symlinks, untrusted owners, and
  group/world-writable command files. Their subprocess environments are cleared;
  the shell rescan receives only a session allowlist plus fixed Omarchy path and
  timeout values. Command correctness is still inherited from the installed
  Omarchy system.
- A persona label in an SSHSIG proof is self-asserted. It is authenticated by
  the signing key but not independently bound to a legal identity.
- There is no revocation or time-stamping service in the first proof version.
- SQLite lifecycle events are protected from ordinary update/delete operations,
  but a process with the user's filesystem authority can replace the database;
  they are local context, not independently witnessed audit evidence.
- A process running as the same user may replace path-based input. The CLI
  hashes before constructing the statement, but the daemon must later accept
  already-open file descriptors for stronger review-to-sign integrity.
- Omarchy packages are copied into private staging before verification and
  extraction, and target directory identity is rechecked before update. Malware
  already running as the same desktop user can still race or modify Omarchy
  configuration, installed plugin files, local receipts, and persona metadata.
- The A Quo install receipt prevents accidental updates of unmanaged or
  Git-managed plugins and records local publisher continuity. It is not signed,
  remotely witnessed, or a defense against same-user malware.
- Package signatures have no trusted timestamp, expiry, transparency witness,
  or TUF freshness metadata yet. Updates require a strictly newer semantic
  version but are not suitable for unattended fetching.
- Archive inspection lists executable files and enforces structural limits; it
  does not statically or dynamically determine whether plugin code is safe.
- An already-enabled plugin may begin loading the explicitly approved update
  when its directory is atomically exchanged. A failed shell rescan restores
  the prior directory, but the approved candidate may have briefly executed.
- The prototype has not completed an external security audit.
