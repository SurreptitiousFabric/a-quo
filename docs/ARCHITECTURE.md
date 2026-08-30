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

## Root-distribution boundary

[Persona-root distribution](ROOT-DISTRIBUTION.md) is portable core evidence,
not a desktop authority service. It keeps three objects separate:

1. the existing signed persona-root proof, which supplies the canonical
   statement, OpenSSH public key, and SSHSIG signature;
2. an unsigned deterministic public card, which copies verified root facts and
   the digest-only `aquo:persona-root-pin:v1:` URI but contains no proof or
   signature; and
3. an unsigned verifier-owned pin record, which preserves the expected root
   digest plus the verifier's reported trust basis, channel, and observation
   time.

Comparison verifies the signed proof, derives the expected card, and then
compares the separately retained verifier state. Signature validity, card
consistency, pin match, channel provenance, timing reminders, and
current-history status remain separate report dimensions. Same-channel copying
is useful for error detection but is not independent trust; an out-of-band
choice reports only user-claimed channel separation.

The canonical JSON, selectable text, print HTML, and digest-only QR forms use
ordinary non-secret files and renderings. A compatible implementation can
verify the signed root with RFC 8785, SHA-256, and generic OpenSSH SSHSIG
tooling, so loss of one A Quo binary, desktop, or operating system does not
make recovery dependent on it. This path does not use the signing daemon,
D-Bus, a credential wallet, or a network service, and it grants no signing,
recovery, legal-identity, current-authority, or artifact-safety claim.

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

The continuity tables introduced in schema v3 add an immutable persona root,
append-only accepted transition proofs, and one compare-and-swap transition
head.
Schema v4 also rejects cross-persona lifecycle-event/key pairings, limits each
key to one origin/retirement/compromise event, and replays stored lifecycle
history before key lookup, signer selection/binding, and lifecycle mutation.
Continuity-managed reads additionally reverify the signed journal and current
head. One native cryptographic pass produces an opaque verified root, ordered
transition sequence, and report; the store then binds every signed value back
to its exact SQLite row, persona label, key ownership, lifecycle replay, and
head revision inside one SQLite snapshot. The live per-persona bounds are 4,097
keys (the root plus the protocol maximum of 4,096 transitions), 12,291
lifecycle events, and 64 MiB of aggregate root/transition proof bytes. Counts
and aggregate bytes are checked before proof blobs are materialized, and key
and event counts are checked before a write reserves another entry. A proposed
append's serialized proof bytes are reserved against the same 64 MiB total
before any key, event, signer-reference, transition, or head mutation. Portable
backups deliberately retain the smaller 256-key/4,096-event policy. Live
journals begin with a newly recorded local root or a separate, explicit,
exact-pin materialization operation; file-only roots and imported evidence are
never silently adopted.

Migration from schema v3 to v4 fails closed if a persona exceeds the live
bounds or its lifecycle rows do not replay exactly, including per-key
timestamps that move backward. The prototype does not silently repair such a
database. Schema-v4 lifecycle writes also refuse a backward local clock before
changing state; signed proof issuance times remain separate and retain their
documented skew policy.

Schema v5 adds one immutable public continuity-evidence archive per persona.
Database triggers prevent that archive from being updated or deleted. The v5
design also prohibited coexistence with a live local continuity root; schema
v9 later permits only receipt-governed explicit materialization. Opening the
store checks the applicable cross-table shape before selected reads;
security-relevant reads of a selected archive then enforce portable bounds and
reverify its exact signed root, policy chain, transitions, derived active tip,
and lifecycle metadata. The archive remains evidence-only and grants neither a
signer reference nor operational authority.

Schema v6 closes SQLite `INSERT OR REPLACE` paths around roots, heads,
transitions, lifecycle events, and signer-reference events. Selected live reads
also reject a changed unsigned persona label, a head revision that differs from
the verified transition count, or any root/intermediate/tip signing key no
longer owned by the same local persona. These checks detect inconsistent local
rewrites; they do not make the user-owned database an independent witness or
detect replacement by a coherent older copy.

Schema v7 adds immutable append-only recovery-policy proofs, a separate
compare-and-swap policy head, and closed tagged routine/recovery transition
rows. A selected live read reverifies the root, complete policy chain, mixed
transition chain, lifecycle state, signer ownership, and both heads before
returning security-relevant state.

Schema v8 adds one immutable terminal-revocation overlay row per persona. The
v7 transition head remains the exact pre-terminal key head; the v8 row is the
effective final head and stores the threshold-signed no-successor proof. SQL
guards reject later transition inserts, policy inserts, and head changes once
that row exists. Selected reads reverify the complete chain including the
terminal leaf and require zero active keys and no signer reference. Keeping a
separate final overlay avoids encoding a dummy successor or weakening the
non-null v7 row shape. Older binaries reject schema v8 rather than silently
treating the pre-terminal key as active.

Schema v9 adds immutable archive-materialization receipts. A retained archive
may coexist with a projected live root only while an exact pending intent is
being completed in one transaction or after that intent has been sealed. Every
selected authority read rechecks the retained bytes, source snapshot, external
pins, imported audit boundary, projected proof prefix, and method-specific
result. The direct-activation method additionally seals a fresh current-tip
custody challenge and local signer binding. Exact replay reads the first sealed
receipt without reopening the signer.

Schema v10 adds the narrow terminal-hydration path. Its insert guard accepts a
terminal overlay only for a matching pending `terminal_hydration` receipt,
exact preterminal SQL head, exact final terminal digest and policy, imported
terminal lifecycle event, and zero local authority. The sealed result retains
the original archive while requiring the exact key set and lifecycle history,
no later key or signer-reference events, no active key or signer reference,
and the exact terminal proof wrapper. The SQL head remains preterminal; the
overlay is the effective final head. Authority-producing APIs report the
persona as permanently terminally revoked rather than treating it as merely
quarantined. These controls are a bounded prototype, not an independent
witness or production-readiness claim.

Schema v11 adds the recovery-activation materialization method. Its receipt
binds the exact recovery-proof wrapper, pinned archive/root/source head/latest
policy, successor binding, and distinct result head. Only a matching pending
intent may project that recovery result. A schema-v2 ceremony proof must be
active during first materialization; the sealed receipt retains the original
materialization time so an exact read-only replay can be validated after the
signed ceremony expiry without exercising authority again. The receipt also
authenticates the retained archive's exact historical source prefix. A
schema-v2 recovery transition already inside that prefix remains inspectable
and migratable after its deadline because it is not being exercised again; the
archive's unsigned `observed_at` values and imported materialization metadata
are not proof of its original commit time. Recovery transitions first added to
an ordinary live journal or after the authenticated archive prefix retain the
strict expiry check.

An accepted rotation uses one immediate transaction to retire the old key,
activate and bind the new key, append lifecycle events and the verified proof,
and advance the head. The candidate's two signatures produce an opaque receipt
before the writer lock; inside the transaction, the current stored chain is
reverified once and that receipt is linked to its exact tip without repeating
the candidate checks. Verification of the old prefix still occupies the writer
transaction pending a safe cross-transaction stored-prefix receipt. Ordinary
key-add and rotation paths are blocked for a
continuity-managed persona. Every snapshot reverifies the portable root,
transition chain, resulting head, active key, and lifecycle history; the
database remains local context rather than an independent witness. Portable
verification may additionally match an independently obtained transition
sequence/digest checkpoint, allowing an older prefix or sibling branch to be
rejected relative to that checkpoint.

Portable recovery policies hold only public fingerprints, thresholds, policy
links, validity claims, and an exact continuity sequence/digest checkpoint.
Recovery private keys remain with their configured OpenSSH, agent, or hardware
providers. The low-level workflow verifies threshold signatures and proposed
new-key custody, while mixed-chain verification requires every policy
checkpoint to match the exact supplied transition prefix. An existing
operational persona can explicitly record an exact, independently pinned policy
chain and commit an already-signed recovery/compromise transition. One
transaction updates old-key lifecycle state, audit events, the new key and
signer reference, and the proof row, then advances the transition head with a
compare-and-swap while requiring the policy head to remain unchanged. Before a
first commit takes that write lock, the configured successor signer signs a
fresh OS-random challenge under a dedicated namespace. A Quo verifies it
against the recovery-approved public key, then rechecks the exact canonical
locator identity inside the transaction before changing old-key authority.
Exact statement retries return the first committed proof wrapper without
accessing the signer, and later routine rotation can continue from that mixed
journal.

The bounded recovery-transition ceremony adds portable coordination around one
such proof. A canonical request carries the complete signed root, policy chain,
prior mixed transition history, exact root/latest-policy/previous-head
expectations, successor public key, and a candidate statement with a signed
random 256-bit ID and strict expiry. It carries no local persona UUID or signer
locator. The request is bounded at 8 MiB. Each full verification pass caps
aggregate embedded root, policy, and transition signature work at 2,048 before
embedded structural processing or cryptographic SSHSIG verification; callers
separately budget repeated passes. Each Linux participant independently
supplies the same three pins, and the daemon derives their recovery-authority
or exact-successor role from their key before direct local consent. The
canonical response carries the
request digest, derived role and fingerprint, the existing transition-statement
signature, and a purpose-separated signature over the exact canonical request;
it omits the persona UUID and locator. Both signatures are self-verified before
deterministic assembly produces the existing proof wrapper without mutating a
store. First live commit of that candidate, or its use as the new one-step
recovery archive activation extension, must finish before the signed expiry;
exact replay of an already committed or sealed result may succeed later without
signer I/O or new authority.

This ceremony covers recovery transitions only. Policy enrollment/update and
terminal revocation remain sequential. Neither the ceremony nor commit proves
trusted time, freshness or independence of caller pins, distinct humans or
devices, hardware custody, legal identity, practical independence of key
holders, or future availability of the successor signer.

Terminal revocation deliberately uses a different proof schema and SSHSIG
namespace. Recovery-policy statement v1 remains replacement-only. Statement
v2 contains explicit capabilities, and only a latest active policy carrying
`terminal_revocation` may authorize the final leaf. A first terminal commit
checks exact root, policy, and previous-head pins, then atomically changes the
last key lifecycle state, removes its signer binding, records the immutable
proof, and freezes both heads. It accepts no successor key or locator. Exact
replay returns the first wrapper without mutating authority. The local database
still cannot detect replacement by a coherent pre-terminal copy; an external
checkpoint or witness remains necessary for that claim.

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
Canonical unsigned persona-root statements use a distinct request type and are
bounded at 64 KiB. Routine transition requests have another distinct message
type. They carry the expected sequence, independently supplied root digest,
expected prior-transition digest, closed next-key provider, bounded signer
locator, and exactly one descriptor containing at most 16 KiB of proposed
public-key text. The daemon constructs the transition statement from its
authoritative journal instead of accepting caller-authored statement bytes.
Recovery participation uses a separate message type and intentionally has no
persona UUID. Its packet carries the participant-local provider, bounded
private signer locator and normalized public key plus independently supplied
root, policy, and previous-head pins. Its one descriptor is the exact sealed,
canonical portable request, bounded at 8 MiB. The locator stays inside this
private local channel; neither the portable response nor the consent prompt
contains it. The daemon reverifies the complete request and pins, derives the
role from the participant key, and self-verifies the resulting response.
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

For routine rotation, the daemon verifies the current journal, old signer, new
public key/provider/locator, caller-supplied root pin, expected sequence, and
previous head before consent and again afterwards. Both keys sign the identical
canonical statement under the transition namespace. The daemon verifies both
signatures and the complete resulting chain, commits the proof and key handoff
atomically, rereads the journal, and only then releases the sealed proof.
Cancellation, disconnection, stale state, substitution, and forks fail closed.
If a response is lost after commit, only an exact retry—same root, sequence,
prior head, new key, provider, and locator—can recover the stored proof without
signing or mutating again.

Daemon and consent UI communicate through inherited pipes using a second
closed, bounded binary protocol. Every prompt contains two UUIDs, a closed
persona purpose, peer credentials, and bounded safe display strings. Artifact
prompts add a closed kind, SHA-256, and size; domain prompts add the exact name,
TXT commitment, and validity times; persona-root prompts add the unique anchor,
root-statement SHA-256, and issuance time. Routine-transition prompts add the
persona anchor, pinned root, sequence, prior chain head, issuance time, old and
new key fingerprints, and exact transition-statement SHA-256. Recovery-
participation prompts use two fixed pages to show the verified persona and
anchor, ceremony ID and expiry, derived role and participant key, root/policy/
head pins, reason, previous and successor keys, and exact request digest. They
contain no coordinator-local persona UUID or participant signer locator. The
response contains only approve/decline/cancel and the matching request UUID.
The child never receives the input descriptor, signer locator, private key,
agent socket, or database handle.

The Linux prompt speaks Wayland directly and renders through a software
framebuffer. It has no D-Bus, portal, GTK/GIO, or AT-SPI dependency. This keeps
the approval action off a shared session bus but leaves the prototype without
screen-reader support; accessibility is a release gate that needs its own
reviewed trusted path.

## Isolated media verification

C2PA verification is an untrusted-parser adapter, not part of the signing
daemon. The CLI opens the media without following a final symlink, creates a
bounded sealed snapshot, and starts a hidden launcher through cleared standard
streams. The launcher independently re-snapshots the stream and requires its
SHA-256 and size to match before it directly executes Bubblewrap.

The Bubblewrap worker has an unshared network and the other supported Linux
namespaces, no capabilities, disabled nested user namespaces, read-only system
libraries, isolated temporary and process filesystems, fixed CPU/address-space/
descriptor/process/core limits, and a parent-enforced wall deadline. It sees a
read-only Bubblewrap copy of the sealed input, not the original pathname or
directory. This prevents sidecar discovery and makes remote fetching
unavailable at the operating-system boundary.

The pinned `c2pa-rs` build also disables default features and enables only file
I/O plus Rust-native crypto. SDK settings independently disable remote and OCSP
fetching, trust verification, timestamp trust, and identity assertion decoding.
The strict response reports local content validity, claim-signature metadata,
certificate trust, CAWG assertion presence, and A Quo persona linkage as
separate dimensions. See [Offline C2PA verification](C2PA.md).

## Isolated software supply-chain verification

Sigstore bundles and trusted roots are another untrusted-parser adapter and do
not enter the signing daemon. The Linux CLI seals independent artifact,
standardized v0.3 bundle, and explicit trusted-root snapshots. It passes only
the artifact SHA-256 and size plus a closed frame containing the two bounded
JSON inputs to a re-executed worker in the same no-network Bubblewrap and fixed
resource boundary used for hostile media parsing.

The worker requires certificate-based verification material, SHA-256 artifact
binding, an inclusion proof and signed checkpoint, a verified signing time,
certificate chain and SCT verification, and exact in-toto Statement v1
semantics. The parent independently applies exact certificate identity and
OIDC issuer equality to the verified response. Standardized bundle format,
artifact binding, cryptography, trust-root selection, identity policy, SLSA
claims, build expectations, and safety remain separate report dimensions.

The pinned verifier has TUF and TLS features disabled and uses a precomputed
artifact digest. Its Rekor and TSA crates still compile non-TLS `reqwest`
client code unconditionally; A Quo never calls it, the worker has no network
namespace, and the entire dependency graph remains outside `a-quo-daemon`.
See [Offline Sigstore and SLSA verification](SUPPLY-CHAIN.md).

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
7. install with Linux atomic no-replace semantics without making an Omarchy
   enable call; race-free unreferenced exposure requires Omarchy cooperation
   through a coordinated transaction or inhibit interface;
8. write a reserved local management receipt that release archives cannot supply;
9. update only an A Quo-managed install, from the same local publisher persona,
   to a strictly newer semantic version;
10. exchange old and new directories atomically, restoring the old directory if
    the Omarchy shell rescan fails; and
11. remove only an unreferenced A Quo-managed directory by atomically
    quarantining it through pinned parent/target/quarantine descriptors,
    attempting exact restore if rescan fails, and retaining the recovery copy
    even after success rather than recursively deleting a mutable path, without
    requiring a still-authorized publisher; and
12. leave enablement and reference changes to separate explicit Omarchy
    decisions without
    claiming that independent configuration changes cannot race directory
    exposure or removal.

Signed does not mean safe. Sandboxing and behavioral review remain separate.
Release-metadata resolution and TUF are later A Quo layers;
behavioural/static code-risk analysis belongs to Plug & Prejudice or another
explicitly attributed reviewer adapter. The direct-Wayland consent UI is
implemented for artifact, domain, persona-root, routine-transition, and
recovery-participation requests, but packaging and an accessible trusted
interaction remain release gates.

## Technology choices

- Rust workspace for memory safety, static binaries, and a shared core.
- Mise for pinned language toolchains and repeatable developer tasks.
- OpenSSH SSHSIG for durable personal and pseudonymous signatures.
- RFC 8785 JCS through `serde_json_canonicalizer` for cross-language persona
  root and transition statement bytes; sequences and timestamps stay within
  JCS's exact IEEE-754 integer range.
- Sigstore/Cosign bundles for public release and CI identity.
- SQLite for non-secret local metadata, an append-oriented audit log, and the
  atomic routine-continuity journal/head transaction.
- Rustix Unix sockets, `SCM_RIGHTS`, peer credentials, and sealed memfds for the
  narrow Linux consent boundary.
- Hickory Resolver with explicit DNSSEC validation, fixed deadlines, and
  bounded answer processing for live domain-control evidence.
- Pinned `c2pa-rs` with default features disabled, plus Bubblewrap and
  `prlimit`, for bounded offline embedded-media verification outside the daemon.
- `winit` (Wayland-only), `softbuffer`, `tiny-skia`, and direct `swash`/`skrifa`
  text rendering for the busless Linux consent process; QML only for
  non-authoritative Omarchy status.
- C2PA for media provenance and in-toto/SLSA for software build provenance,
  without treating either as creator identity or artifact safety.
- TUF metadata before unattended or security-sensitive updates.
