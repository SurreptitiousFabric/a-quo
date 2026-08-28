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
- Embedded C2PA media is parsed only in a separate no-network Linux namespace
  from a hash-checked sealed snapshot; it never enters the signing daemon or
  consent process.
- Sigstore bundles and trusted roots are parsed only in a separate no-network
  Linux namespace from hash-checked sealed snapshots; only the artifact digest,
  not artifact bytes, enters the crypto worker.
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
- Trusted local consent for persona-root creation proves only that the user
  approved that exact fresh root through A Quo's packaged UI. The root remains
  self-asserted, deliberately correlates later persona activity, and has no
  external trust until a verifier independently obtains and pins its statement
  digest. Two-key transition consent is not yet implemented.
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
- A domain-control proof is exact-name and short-lived. Only a matching TXT
  RRset validated to a DNSSEC trust anchor establishes authenticated current
  control; an unsigned match is labeled as an observation. CNAME-target data,
  parent and child names, registrant identity, legal ownership, website
  content, historical control, and trusted time remain outside the claim.
- Live domain verification sends the public queried name to the operating
  system's configured recursive resolver over ordinary DNS with TCP fallback.
  DNSSEC protects authenticity, not query confidentiality. Resolver failure,
  timeout, and over-limit responses remain distinct from authenticated absence.
- Archive inspection lists executable files and enforces structural limits; it
  does not statically or dynamically determine whether plugin code is safe.
- C2PA verification is limited to a 128 MiB local embedded asset. The worker
  does not fetch remote or sidecar manifests, check certificate or timestamp
  trust, query revocation, decode or validate CAWG identity, or link the claim
  to an A Quo persona. `valid` therefore means content binding only.
- The C2PA worker is bounded by Linux namespaces, no capabilities, disabled
  nested user namespaces, fixed resource limits, closed output, and a wall
  deadline, but it does not yet use a syscall seccomp allowlist. It inherits the
  correctness of the kernel, fixed system-owned Bubblewrap and `prlimit` tools
  (UID 0, or overflow UID 65534 when root is unmapped), Rust cryptographic
  dependencies, and the C2PA parser.
- Bubblewrap copies the sealed C2PA input into a read-only in-memory sandbox
  file. The 128 MiB cap bounds peak copies, but large video support remains
  deliberately unavailable pending a safer immutable streaming design.
- Sigstore verification requires an owner-supplied trusted-root snapshot. A Quo
  fingerprints it but does not establish its source, freshness, later
  revocations, or suitability for a publisher. No network or TUF update occurs
  inside verification.
- The first Sigstore slice accepts only standardized v0.3 certificate bundles,
  SHA-256 blob signatures or one-signature in-toto Statement v1 envelopes, and
  certificates with verifiable SCTs. Managed-key hints, legacy bundles, other
  digest algorithms, and private trust domains without SCTs are unavailable.
- `sigstore-verify` is isolated to the CLI adapter. Its Rekor and TSA crates
  compile `reqwest` JSON/form client code even with TLS and TUF features
  disabled. A Quo never constructs those clients, and the worker's unshared
  network namespace is the authority preventing network access.
- Sigstore cryptography inherits `sigstore-verify`, `aws-lc-rs`, and AWS-LC.
  Worker isolation limits parser and network blast radius; it cannot establish
  the cryptographic correctness of those implementations.
- Authenticated SLSA fields remain claims. The prototype checks required v1
  shapes and reports builder/build type, but has no independent builder-level,
  source, build-type, or external-parameter expectation policy and therefore
  assigns no SLSA Build level.
- The Sigstore worker uses the same fixed Bubblewrap/prlimit trust assumptions
  and lacks a syscall seccomp allowlist. Artifact snapshots are capped at 512
  MiB even though only their digest enters parsing; larger release artifacts
  are deliberately unsupported.
- An already-enabled plugin may begin loading the explicitly approved update
  when its directory is atomically exchanged. A failed shell rescan restores
  the prior directory, but the approved candidate may have briefly executed.
- The prototype has not completed an external security audit.
