# Architecture

## Design goal

A Quo gives one coherent experience across several kinds of evidence without
pretending they are one identity system. A user chooses a persona, approves a
specific statement, and receives a portable proof. Verifiers report each
evidence dimension independently.

## Components

```text
Untrusted callers                 Trusted local boundary

Omarchy bar ─┐                    ┌─ consent UI (separate GTK process)
CLI/app  ────┼─ D-Bus request ───┼─ a-quo-daemon
browser  ────┘                    │    ├─ persona policy
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
events in SQLite. It does not store official wallet credentials. Private keys
remain in hardware, an SSH agent, a platform keystore, or a purpose-built
encrypted provider. The local history is append-only through the application
schema, but is not a remotely witnessed or cryptographically tamper-evident
ledger.

The later daemon exposes narrow D-Bus methods. It never returns a raw private
key. File descriptors are preferred over mutable paths when a caller asks to
sign local content, preventing a file-swap race between review and signing.

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
- D-Bus on Linux for explicit process boundaries.
- GTK4/libadwaita for trusted Linux consent; QML only for Omarchy status.
- C2PA for media provenance and in-toto/SLSA for software build provenance.
- TUF metadata before unattended or security-sensitive updates.
