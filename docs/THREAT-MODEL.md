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
- The Linux consent protocol is a closed, versioned Unix-socket protocol with
  bounded fields, exactly one passed file descriptor, kernel peer credentials,
  and fail-closed handling of unknown message types or trailing bytes.
- The reviewed artifact is a size-bounded sealed memfd snapshot. Caller paths,
  names, size claims, and mutable descriptors are never the signing authority.
- Signer selection requires one active persona key, an explicitly bound local
  locator revalidated at use time, and post-sign verification against the
  registered public key before a proof is released.
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
  the accepted executable and any operating-system askpass implementation
  remains inherited from the operating system. A key-unlock prompt is separate
  from A Quo consent and receives no A Quo evidence or session-bus address.
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
- Signer-reference history records that a binding changed but deliberately does
  not retain old paths. The current path is private local metadata, not proof of
  key custody or hardware backing.
- The lower-level `sign` command remains path-based and does not provide the
  daemon's stronger review-to-sign guarantee. The Linux `request-sign` client
  uses an already-open descriptor, positional before/after hashes, and local
  verification of the returned proof. Its direct-Wayland helper must still be
  installed at the fixed root-owned package path; a source checkout therefore
  remains fail-closed.
- The first direct-Wayland UI deliberately has no AT-SPI bridge because that
  would add a session-bus action path to a security decision. It consequently
  lacks screen-reader support. A generally available release needs a reviewed
  accessible interaction that does not let unrelated session processes invoke
  approval actions.
- Unix socket mode and `SO_PEERCRED` reject other users but cannot distinguish
  honest and malicious processes running as the same desktop user. Caller
  executable details are display evidence only; human consent and key policy
  remain the authorization boundary.
- Normal listener teardown removes only its own verified socket inode. An
  abrupt process death can leave a stale path; the daemon refuses to unlink it
  automatically until signal-aware cleanup or user socket activation is
  packaged.
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
