# Architecture

## Design goal

A Quo gives one coherent experience across several kinds of evidence without
pretending they are one identity system. A user chooses a persona, approves a
specific statement, and receives a portable proof. Verifiers report each
evidence dimension independently.

## Components

```text
Untrusted callers          Private per-user channel       Trusted local boundary

Omarchy bar ─┐             AF_UNIX SOCK_SEQPACKET     ┌─ consent UI (separate GTK process)
CLI/app  ────┼─ exact protocol + SCM_RIGHTS ─┼─ a-quo-daemon
browser  ────┘              SO_PEERCRED           │    ├─ persona policy
                                               │    ├─ signer adapters
                                               │    └─ metadata database
                                               └─ hardware / agent / official wallet

Portable verifier: artifact + proof bundle + trust policy -> evidence report
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

The daemon will not use D-Bus for signing or consent. On Linux it will listen on
a mode-0600 Unix `SOCK_SEQPACKET` socket inside a mode-0700 A Quo directory under
`XDG_RUNTIME_DIR`. The implemented closed, versioned protocol has fixed message
types and field bounds: no variant maps, object registry, broadcasts, or
extension bag.

A request carries exactly one file descriptor with `SCM_RIGHTS`. The implemented
Linux transport checks `SO_PEERCRED`, rejects cross-user peers, copies
regular-file content into a hard-bounded sealed memfd, and derives the digest
from that immutable snapshot. Peer credentials provide attribution, not
authorization: any same-user process may be hostile, so every signature still
requires the separate trusted UI. An approval response carries one sealed proof
descriptor; a typed rejection carries none. Neither response exposes a private
key or attacker-controlled error text.

The artifact kind sent for consent is inert display context. The signed v1
statement remains a generic artifact claim; formats such as website ownership
must add their own signed, domain-separated statement rather than relying on a
label shown in the prompt.

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
Network resolution, freshness metadata, TUF, static code-risk analysis, and the
trusted consent GUI are later layers; the current CLI does not imply them.

## Technology choices

- Rust workspace for memory safety, static binaries, and a shared core.
- Mise for pinned language toolchains and repeatable developer tasks.
- OpenSSH SSHSIG for durable personal and pseudonymous signatures.
- Sigstore/Cosign bundles for public release and CI identity.
- SQLite for non-secret local metadata and an append-oriented audit log.
- Rustix Unix sockets, `SCM_RIGHTS`, peer credentials, and sealed memfds for the
  narrow Linux consent boundary.
- GTK4/libadwaita for trusted Linux consent; QML only for Omarchy status.
- C2PA for media provenance and in-toto/SLSA for software build provenance.
- TUF metadata before unattended or security-sensitive updates.
