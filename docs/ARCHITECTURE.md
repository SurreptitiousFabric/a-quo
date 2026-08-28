# Architecture

## Design goal

A Quo gives one coherent experience across several kinds of evidence without
pretending they are one identity system. A user chooses a persona, approves a
specific statement, and receives a portable proof. Verifiers report each
evidence dimension independently.

## Components

```text
Untrusted callers          Private per-user channel       Trusted local boundary

Omarchy bar ─┐             AF_UNIX SOCK_SEQPACKET     ┌─ consent UI (direct Wayland process)
CLI/app  ────┼─ exact protocol + SCM_RIGHTS ─┼─ a-quo-daemon
browser  ────┘              SO_PEERCRED           │    ├─ persona policy
                                               │    ├─ signer adapters
                                               │    └─ metadata database
                                               └─ hardware / agent / official wallet

Portable verifier: artifact/domain evidence + proof bundle + trust policy -> report
```

The Omarchy plugin is presentation only. Omarchy plugins can execute arbitrary
shell commands in the user's session, so neither secrets nor trusted consent
decisions may live in the plugin process.

## Portable core

`a-quo-core` owns artifact descriptions, proof parsing, cryptographic adapter
interfaces, and evidence reports. It must remain usable without Omarchy and
without a desktop. Platform applications call this core rather than inventing
their own proof semantics.

The initial signer is OpenSSH SSHSIG because it is mature, locally available on
Omarchy, supports FIDO security keys, and produces offline-verifiable proofs.
Sigstore bundles, C2PA manifests, and wallet presentations are adapters—not a
replacement for the common evidence model.

## Personas and correlation

A persona has its own key or issuer relationship. Personal, pseudonymous,
project, employer, and government-facing personas must not share a universal
identifier. Linking two personas is an explicit, separately signed act.

## Key custody

A Quo stores public verification material, policy, labels, and local lifecycle
events in SQLite. It may store an explicitly configured local signer path, but
never reads or copies private-key or hardware-stub contents into the database.
It does not store official wallet credentials. Private keys remain in hardware,
an SSH agent, a platform keystore, or a purpose-built encrypted provider. The
local history is append-only through the application schema, but is not a
remotely witnessed or cryptographically tamper-evident ledger.

Signer selection requires exactly one active key for the chosen persona and a
safe current locator for that key. Locator safety is rechecked at use time, and
every resulting signature is verified against the registered public key before
the proof is released.

The daemon does not use D-Bus for signing or consent. On Linux its standalone
listener binds a mode-0600 Unix `SOCK_SEQPACKET` socket inside a mode-0700 A Quo
directory under `XDG_RUNTIME_DIR`. The implemented closed, versioned protocol
has fixed message types and field bounds: no variant maps, object registry,
broadcasts, or extension bag.

A request carries exactly one purpose-specific file descriptor with
`SCM_RIGHTS`. The implemented Linux transport checks `SO_PEERCRED`, rejects
cross-user peers, copies regular-file content into a purpose-bounded sealed
memfd, and derives the digest from that immutable snapshot. Artifact inputs are
bounded at 512 MiB; canonical unsigned domain statements are bounded at 4 KiB.
Peer credentials provide attribution, not authorization: any same-user process
may be hostile, so every signature still requires the separate trusted UI. An
approval response carries one sealed proof descriptor; a typed rejection
carries none. Neither response exposes a private key or attacker-controlled
error text.

The artifact kind sent for consent is inert display context. The signed v1
statement remains a generic artifact claim. DNS control therefore uses its own
implemented message type and signed namespace. It binds an exact canonical
name, fresh nonce, short validity window, persona, and key to a derived TXT
commitment; it never upgrades into legal ownership or general website control.

The serial Linux daemon composes this transport with immutable snapshots,
active-signer resolution, post-sign verification, sealed proof responses, and
typed failure codes. Socket I/O has a 10-second bound and signer subprocesses a
120-second bound. Its production approval backend launches only the fixed,
root-owned packaged helper. A missing or unsafe helper is a typed fail-closed
condition; test approvals exist only inside test processes.

Daemon and consent UI communicate through inherited pipes using a second
closed, bounded binary protocol. Every prompt contains two UUIDs, a closed
persona purpose, peer credentials, and bounded safe display strings. Artifact
prompts add a closed kind, SHA-256, and size; domain prompts add the exact name,
TXT commitment, and validity times. The response contains only
approve/decline/cancel and the matching request UUID. The child never receives
the input descriptor, signer locator, private key, agent socket, or database
handle.

The Linux prompt speaks Wayland directly and renders through a software
framebuffer. It has no D-Bus, portal, GTK/GIO, or AT-SPI dependency. This keeps
the approval action off a shared session bus but leaves the prototype without
screen-reader support; accessibility is a release gate that needs its own
reviewed trusted path.

Hyprwire or hyprtavern may later provide optional discovery after their APIs are
stable. They will not replace the private authorization channel. macOS will use
a corresponding private Unix transport; Windows will use a restrictive
named-pipe transport behind the same typed request model.

## Trust is a vector

Reports keep these questions separate:

1. Do the bytes match the signed artifact digest?
2. Is the cryptographic signature valid?
3. Which key or issuer made the statement?
4. What identity evidence, if any, binds that key to a person or organization?
5. Was the key trusted for this purpose at signing time and is it trusted now?
6. Is there build provenance, review evidence, or reproducibility evidence?
7. Is the proof fresh, expired, superseded, or revoked?
8. What runtime permissions and behavior remain risky?

The user interface must never compress these into a green “safe” badge.

## Omarchy release path

The guarded adapter currently:

1. accepts a local immutable `.tar.zst` release rather than a moving branch;
2. copies it once into a private staging directory on the destination filesystem;
3. verifies the staged bytes and requires an active locally recognized publisher;
4. reject unsafe archive paths, links, and unexpected file types;
5. run Omarchy's own plugin manifest validation;
6. show publisher evidence, executable files, and unresolved risk;
7. install with Linux atomic no-replace semantics in a disabled state;
8. write a reserved local management receipt that release archives cannot supply;
9. update only an A Quo-managed install, from the same local publisher persona,
   to a strictly newer semantic version;
10. exchange old and new directories atomically, restoring the old directory if
    the Omarchy shell rescan fails; and
11. leave first enablement to a separate explicit Omarchy decision.

Signed does not mean safe. Sandboxing and behavioral review remain separate.
Release-metadata resolution, TUF, and static code-risk analysis are later
layers. The direct-Wayland consent UI is implemented for artifact and domain
requests, but packaging and an accessible trusted interaction remain release
gates.

## Technology choices

- Rust workspace for memory safety, static binaries, and a shared core.
- Mise for pinned language toolchains and repeatable developer tasks.
- OpenSSH SSHSIG for durable personal and pseudonymous signatures.
- Sigstore/Cosign bundles for public release and CI identity.
- SQLite for non-secret local metadata and an append-oriented audit log.
- Rustix Unix sockets, `SCM_RIGHTS`, peer credentials, and sealed memfds for the
  narrow Linux consent boundary.
- Hickory Resolver with explicit DNSSEC validation, fixed deadlines, and
  bounded answer processing for live domain-control evidence.
- `winit` (Wayland-only), `softbuffer`, `tiny-skia`, and direct `swash`/`skrifa`
  text rendering for the busless Linux consent process; QML only for
  non-authoritative Omarchy status.
- C2PA for media provenance and in-toto/SLSA for software build provenance.
- TUF metadata before unattended or security-sensitive updates.
