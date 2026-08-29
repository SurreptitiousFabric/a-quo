# Portable persona continuity v1

## Status and meaning

A Quo implements portable v1 proofs for routine key handoff and threshold
recovery. A routine transition is signed by both the old and new keys. A
recovery transition is signed by the configured threshold of recovery-only
keys and by the proposed new online key.

It is not legal identity, key non-revocation, or proof that the root or latest
recovery policy was trusted at a useful time. A verifier must obtain the
expected root-statement SHA-256 through a separate trusted channel. Copying the
digest out of the same untrusted proof collection is a consistency check, not
independent pinning.

A root pin identifies the persona history but does not identify its latest
known tip. Root-only verification therefore accepts a valid historical prefix
and cannot choose between two fully signed sibling branches. Where a verifier
has separately obtained an exact head checkpoint, `chain-verify` and
`recovery-chain-verify` can additionally require its transition sequence and
statement digest. Matching that checkpoint detects an older prefix or a
different branch relative to the checkpoint; it still does not prove that no
newer transition exists after it, reveal another authorized but undisclosed
sibling branch, or establish that the checkpoint source was fresh.

On Linux, `root-request` sends the exact canonical root statement through the
private daemon and requires a root-specific direct-Wayland approval before the
registered active key signs. The daemon reviews persona, key, canonical bytes,
and a five-minute clock window both before consent and immediately before
signing. It records the verified root in the continuity tables introduced by
database schema v3. Schema v4 adds lifecycle-audit ownership and replay
guards, schema v5 adds immutable evidence-archive storage, schema v6 closes
replacement-write paths, and the current schema v7 adds immutable live
recovery-policy rows and tagged mixed transitions. Evidence archives remain
mutually exclusive with a live local continuity root. Only after the root
transaction commits does the daemon return a sealed proof. The client verifies
both the result and its journal entry before creating the output file. An
identical retry exports the recorded proof; a different existing output is
never overwritten.

For a newly journaled live history, Linux `transition-request` provides trusted
local two-key consent and atomic lifecycle coordination. It works for a routine
chain and can continue from a recovery transition explicitly committed through
the live-store workflow. The caller must supply `--expected-root-sha256`; the
local journal can require that it matches, but cannot prove that the caller
obtained it independently. The trusted prompt shows the persona and anchor,
purpose, sequence and issuance time, pinned root, previous chain head, old and
new key fingerprints, exact transition-statement digest, request identifier,
and caller credentials.

The prototype enables rotation approval only when the complete review fits in
both its window and a known current output of at least 780 by 900 logical
pixels. Unknown, smaller, or heavily scaled outputs show only a fail-closed
notice and decline/cancel controls. This avoids approving clipped evidence; a
responsive and accessible trusted review remains release work.

After approval, the daemon rechecks the journal head, current signer, candidate
key and signer locator. The old and new keys then sign identical canonical
statement bytes. The daemon verifies both signatures and the resulting full
chain before one immediate SQLite transaction retires the old key, activates
and binds the new key, appends key events and the proof, and advances a
compare-and-swap journal head. It returns the proof only after rereading and
reverifying the committed result.

Cancellation and disconnection before commit leave the head unchanged. A crash
or lost response after commit can be recovered by retrying the exact intent:
the daemon returns the already committed proof without asking either key to sign
again. A changed root, sequence, previous head, key, provider, locator, or proof
is not an idempotent retry and fails closed. Stale heads, forks, substituted
public keys, one-key proofs, and altered metadata are rejected.

This is a bounded Linux prototype, not a release-ready ceremony. It does not
adopt older roots that exist only as files or quarantined evidence archives.
`root-create`, `transition-create`, recovery-policy management, and
recovery-transition creation remain low-level commands that invoke key paths
directly. In particular, `transition-create` produces valid portable two-key
evidence but does not provide the daemon's trusted review, journal, or atomic
key-transfer guarantees. An existing operational persona can explicitly record
an independently pinned signed policy chain and atomically commit an
already-signed recovery/compromise transition. That records evidence; it does
not provide trusted multi-party consent. The local lifecycle command still
refuses to mark the current head compromised out of band. A signed compromise
transition can replace it with a proven successor, but terminal no-successor
revocation is not implemented.

## Persona root

A new root contains:

- `schema`: `urn:a-quo:statement:persona-root:v1`;
- `canonicalization`: `RFC8785`;
- a fresh random 256-bit `persona_anchor` in unpadded Base64url;
- a bounded, self-asserted persona label;
- `root_version` 1;
- a non-negative issuance time within RFC 8785's exact integer range; and
- the initial OpenSSH public-key fingerprint.

The statement is serialized with RFC 8785 JSON Canonicalization Scheme and
signed by the initial key under SSHSIG namespace `a-quo-persona-root-v1`. The
proof embeds the canonical payload, signature, and normalized public key. Its
root identifier is the lowercase SHA-256 of the canonical statement bytes—not
of incidental JSON whitespace or the nondeterministic SSH signature.

The anchor is random per persona. It is never derived from a user account,
device, legal identity, wallet, public key, or another persona. Publishing it
deliberately correlates that one persona's transitions.

## Routine transition

Each transition statement contains:

- `schema`: `urn:a-quo:statement:persona-transition:v1`;
- the same canonicalization, persona anchor, label, and exact root digest;
- a sequence starting at 1 with no gaps;
- a non-decreasing issuance time;
- the previous transition's statement digest, except at sequence 1;
- distinct previous and next key fingerprints; and
- the closed reason `routine`.

The previous and next keys independently sign identical canonical bytes under
SSHSIG namespace `a-quo-persona-transition-v1`. The next-key signature proves
custody of the proposed key; the old-key signature authorizes the handoff. A
root signature, artifact signature, or domain-control signature cannot be
substituted for either role.

Transition arrays are order-insensitive internally, but must contain exactly
one `previous` and one `next` signature. Chain order is external and exact. A
chain verifier rejects missing, repeated, reordered, or skipped sequences;
wrong roots, anchors, labels, current keys, or previous-statement digests; time
regression; duplicate roles; unknown fields; noncanonical JCS or Base64url;
fingerprint substitution; and invalid SSHSIG values.

The local continuity journal is separate from the portable v1 proof format. Its
root is immutable, its accepted transition rows are append-only, and every
routine-journal snapshot used by the trusted path reverifies the stored root,
transitions, claimed head, active key, and lifecycle-event replay. Once a
persona has a journaled root, ordinary local key-add and key-rotation operations
cannot bypass the proof-authorized routine rotation path. The journal is still
user-owned SQLite state, not a remotely witnessed or tamper-proof ledger.

## Attack semantics and current evidence

These names distinguish malformed or partially rewritten history, which A Quo
can reject locally, from a coherent older history, which needs evidence held
outside that history.

| Attack | Current fail-closed behavior | Boundary that remains |
| --- | --- | --- |
| Rollback or truncation | Missing interior links, a stored tail removed beneath a newer head, and a head moved behind retained rows are rejected. A separately expected head also rejects a valid older prefix. | Root-only verification accepts a valid prefix. Replacing the whole database with a coherent older copy is undetectable without an external checkpoint or witness. |
| Fork | A stale or competing local commit is rejected, and a separately expected head rejects a different fully signed sibling branch relative to that pin. | A root or head pin selects one branch; neither can reveal that the signer also authorized and withheld another valid sibling branch. |
| Reordering | Sequence, previous-digest, current-key, and stored-row checks reject every non-identity ordering in the bounded test matrix. | A coherent replacement of all local state remains an external-witness problem. |
| Duplicate transition or lifecycle event | Transition sequence/digest uniqueness blocks ordinary duplicates; full-chain verification rejects disguised duplicates. Schema-v4 lifecycle indexes block repeated origin, retirement, or compromise events, and read-time replay rejects malformed older rows. | The local database is not a transparency service. |
| Cross-persona splice | Root/anchor/key checks reject foreign transition proofs. Schema v4 requires a lifecycle event's key to belong to that event's persona, and reads recheck the relationship. | A user who intentionally publishes two personas as linked has created separate evidence outside this automatic check. |
| Interrupted write | One SQLite transaction covers proof, key transfer, lifecycle events, signer binding, and head update. Real subprocess-abort tests establish an entirely old state before commit and an entirely new, exactly replayable state after commit. | Hardware, filesystem, and SQLite correctness remain trusted; independent review and broader platform fault testing are pending. |

The tests also enumerate strict prefixes, every single-transition omission,
duplicate insertion positions, all non-identity permutations of a
three-transition routine chain, a fully signed sibling fork, and cross-persona
splices. This remains bounded deterministic property evidence.

The shipped hostile-byte parsers for root and routine-transition statements,
root/routine/recovery proofs, the routine-or-recovery transition union, and
persona backups also have coverage-guided targets in [`fuzz/`](../fuzz/).
Synthetic tracked seeds reach every supported proof variant without invoking
`ssh-keygen`. The pinned smoke task permits up to 25,000 mutations and 120
seconds per target, with per-input time, allocation, and RSS limits. It requires
round-trip invariants, canonical signed payloads, lifecycle replay, and bounded
printable-ASCII error messages. The canonical hosted task enables AddressSanitizer
and LeakSanitizer. A named local fallback disables only leak detection where a
managed `ptrace` environment makes LSan abort. This remains a bounded campaign,
not sustained fuzzing or an external security review.

## Threshold recovery and policy continuity

Recovery policy v1 is enrolled by distinct recovery-only OpenSSH public keys,
with proof of possession from every listed key and a threshold of at least two.
A successor policy advances exactly one version, names the exact previous
policy digest, and requires signatures from both the old and new authority sets
under separate SSHSIG namespaces.

Policies sign a `continuity_checkpoint` containing a transition sequence and
the exact statement digest at that position. A recovery under a policy must be
after that policy's checkpoint. If the policy has a successor, the recovery
must also be within the prefix ratified by the successor checkpoint. Mixed-chain
verification checks every checkpoint against the supplied transition bytes;
policy-only verification explicitly does not make that claim.

A recovery transition names the exact policy version/digest, replaces the
current online key through the configured distinct-key threshold, and requires
the proposed new key to sign the same canonical statement. The policy keys,
new online key, and replaced online key must remain distinct. Policy expiry is
checked against the transition's signed time, but neither that time nor policy
freshness is externally trusted by this protocol alone.

The mixed verifier rejects any recovery-authority fingerprint that was also
used as an online persona key anywhere in the supplied history; it does not
prove that different fingerprints are controlled by independent holders.

## CLI

```text
a-quo continuity root-request --persona-id PERSONA_ID \
  --output NEW_ROOT_PROOF

a-quo continuity transition-request --persona-id PERSONA_ID \
  --expected-root-sha256 DIGEST_FROM_SEPARATE_TRUSTED_CHANNEL \
  --next-key NEW_KEY --next-public-key NEW_KEY.pub \
  --next-provider openssh-file --output NEW_TRANSITION_PROOF

a-quo continuity root-create --persona LABEL --key KEY \
  --public-key KEY.pub --output NEW_ROOT_PROOF
a-quo continuity root-verify ROOT_PROOF

a-quo continuity transition-create --root ROOT_PROOF \
  [--prior-transition PROOF ...] \
  --previous-key OLD_KEY --previous-public-key OLD_KEY.pub \
  --next-key NEW_KEY --next-public-key NEW_KEY.pub \
  --output NEW_TRANSITION_PROOF
a-quo continuity transition-verify TRANSITION_PROOF

a-quo continuity chain-verify --root ROOT_PROOF \
  [--transition PROOF ...] \
  --expected-root-sha256 DIGEST_FROM_SEPARATE_TRUSTED_CHANNEL \
  [--expected-head-sequence N \
   --expected-head-sha256 HEAD_DIGEST_FROM_SEPARATE_TRUSTED_CHANNEL]

a-quo continuity recovery-policy-create --root ROOT_PROOF \
  [--prior-transition ROUTINE_PROOF ...] \
  --threshold M --valid-days DAYS \
  --authority-key KEY --authority-public-key KEY.pub ... \
  --output POLICY_PROOF

a-quo continuity recovery-policy-update --root ROOT_PROOF \
  --policy POLICY_PROOF ... --transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 POLICY_PIN \
  --threshold M --valid-days DAYS \
  --previous-authority-key KEY --previous-authority-public-key KEY.pub ... \
  --current-authority-key KEY --current-authority-public-key KEY.pub ... \
  --output NEXT_POLICY_PROOF

a-quo continuity recovery-transition-create --root ROOT_PROOF \
  --policy POLICY_PROOF ... --prior-transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 POLICY_PIN \
  --reason recovery --authority-key KEY --authority-public-key KEY.pub ... \
  --next-key NEW_KEY --next-public-key NEW_KEY.pub --output TRANSITION_PROOF

a-quo --store STORE continuity recovery-policy-record \
  --persona-id PERSONA_ID --policy POLICY_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 POLICY_PIN \
  --expected-head-sequence N [--expected-head-sha256 HEAD_PIN]

a-quo --store STORE continuity recovery-transition-commit \
  --persona-id PERSONA_ID --proof RECOVERY_TRANSITION_PROOF \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 POLICY_PIN \
  --expected-previous-head-sequence N \
  [--expected-previous-head-sha256 HEAD_PIN] \
  --next-provider openssh-file --next-signing-locator NEW_KEY

a-quo continuity recovery-chain-verify --root ROOT_PROOF \
  --policy POLICY_PROOF ... --transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 POLICY_PIN \
  [--expected-head-sequence N --expected-head-sha256 HEAD_PIN]
```

`root-request` and `transition-request` are the trusted Linux journal flows and
require the private daemon plus packaged consent helper. `--next-provider` is
closed to `openssh-file`, `ssh-agent`, or `fido2`. The proposed public key is
passed as a bounded descriptor; the daemon constructs the statement from its
authoritative journal rather than accepting caller-authored transition bytes.
The signing key or SSH-agent/FIDO stub named by `--next-key` must match
`--next-public-key` and the selected provider.

`recovery-policy-record` and `recovery-transition-commit` are explicit
live-store evidence-adoption flows, not consent ceremonies. They require exact
root, latest-policy, and current/previous-head pins; a nonzero head requires its
digest and sequence zero forbids one. Policy proofs can only extend the
immutable recorded prefix. A new policy append and a first recovery commit
require the live latest policy to remain active at their respective verified
record or commit clocks. A first recovery commit atomically changes lifecycle
state, binds the proven next key, appends the proof, and advances the head.
Replaying the same canonical statement returns the first committed wrapper and
may succeed after the named policy expires or a later policy supersedes it,
provided the caller pins the live latest policy and the committed recovery
statement remains the fully verified current transition head; replay grants no
new authority. The provider and signer locator are required as a pair for a
first commit. Both may be omitted only for that exact replay; A Quo then reuses
the stored binding metadata while still verifying the submitted proof wrapper.
Supplying only one fails, and an explicitly supplied replay pair must match the
stored metadata. Exact replay of an already recorded policy may likewise
succeed after expiry because it changes no authority. Neither command operates
on a quarantined evidence archive.

Before a first recovery commit changes authority, the configured successor
signer must sign a fresh local challenge that A Quo verifies against the
recovery-approved public key. The canonical locator identity is checked again
inside the write transaction before the old key changes state. An SSH agent or
hardware signer must therefore be available for a first commit. Exact replay
does not access the signer and may still work after its target disappears.

`transition-verify` establishes two valid signatures over one statement but
does not claim that the statement belongs to a trusted root or ordered chain.
`chain-verify` additionally checks every link and the caller-supplied expected
root digest. Without an expected head it describes the key at the supplied
chain tip and explicitly reports that newer or competing history may have been
withheld. A nonzero `--expected-head-sequence` requires
`--expected-head-sha256`; sequence zero names the root and must omit the head
digest. The checkpoint must come from a separate trusted channel to add more
than an internal consistency check. A matching head rejects other branches
relative to that pin; it cannot reveal a simultaneously authorized and withheld
sibling branch. Reports still list that competing-branch uncertainty, pin
timing/source, legal identity, current authorization/non-revocation, recovery
authority, and artifact safety as not established.

Proof inputs are bounded, must be regular files, and are opened without
following symlinks on Linux. New proof outputs use mode 0600 on Unix and are
file-synced; on Linux the atomic writer also syncs the destination directory.
Journal-flow retries accept an existing output only when it is the exact
recorded proof; other outputs are never overwritten. Proof contents are public
verification material but correlate the selected persona.

For low-level CLI commands that accept repeated continuity or recovery inputs,
the count ceilings are checked before any supplied path is opened. The command
then enforces a 64 MiB aggregate raw proof/public-key input ceiling
simultaneously with the 1 MiB per-proof, 16 KiB per-public-key, 4,096-transition,
1,024-policy-version, and 32-recovery-authority ceilings. It also permits at
most 2,048 cryptographic signature verifications across every repeated
verification pass made by one command. A minimum-work calculation from path
and signer counts runs before file I/O; after closed structural parsing, the
exact signature cardinality is checked before the first cryptographic
verification. Limit failure never truncates the requested history.

These are operational resource limits, not protocol-validity claims: passing
them does not make a proof valid, and a proof does not become cryptographically
invalid merely because a particular CLI invocation exceeds an aggregate
resource budget. The 2,048-verification ceiling applies to the low-level
file-based commands, not selected live SQLite-journal operations. A live
journal is separately bounded to 64 MiB of aggregate root/transition proof
bytes, checked with its 4,096-transition ceiling before proof blobs are
materialized. One cold pass over the maximum routine journal performs one root
plus 8,192 transition-signature checks (8,193 in-process checks), verifies each
proof exactly once, and returns an opaque verified sequence. Appending at a
verified tip checks the candidate proof's two signatures once and retains an
opaque receipt. The current stored prefix is then reverified inside the
immediate write transaction, and the receipt is linked to that exact head
without repeating the candidate signatures. This still holds the SQLite writer
reservation while the existing chain is checked. Daemon, CLI, and Omarchy
checkpoints may also revalidate at separate times; safe cross-transaction reuse
of a stored-prefix receipt and a request-wide crypto-work budget remain
hardening work.

The Linux root and routine-transition requests use separate closed IPC messages
and sealed descriptors; they cannot be confused with artifact or domain-control
signing, or with each other.
The trusted prompt shows the persona, purpose, unique anchor, root-statement
digest, issuance time, initial key fingerprint, request UUID, and caller PID/UID.
It warns that publishing the durable root links future activity and proves
neither legal identity, recovery authority, nor safety.

## Standards and implementation

- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) defines the JCS byte
  representation.
- The JCS reference project's [implementation list](https://github.com/cyberphone/json-canonicalization)
  identifies `serde_json_canonicalizer` for Rust.
- [OpenSSH SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
  defines detached signatures and purpose-separating namespaces.

A Quo uses `serde_json_canonicalizer` 0.3.x, locked by Cargo, rather than
sorting object keys itself. Sequence numbers are `u32`; accepted timestamps are
bounded to non-negative integers no greater than `2^53 - 1`, avoiding the JCS
IEEE-754 integer-precision trap. Payloads are limited to 64 KiB, individual
proof files to 1 MiB, individual signature strings to 64 KiB, and chains to
4,096 transitions. Proof and statement byte parsers enforce their limits before
JSON deserialization, suppress raw attacker-controlled parser text in
diagnostics, and complete structural preflight before native cryptographic work
for that chain. Verification accepts Ed25519, ECDSA P-256/P-384/P-521, 2,048-
through 4,096-bit RSA with RSA-SHA2 signatures, and OpenSSH FIDO Ed25519/P-256
keys. DSA, RSA-SHA1, unknown algorithms, and RSA keys outside that size range
fail closed. OpenSSH `ssh-keygen` remains the signing boundary so agent-backed
and hardware-backed private keys stay with their provider. Chain-level
sequence, linkage, checkpoint, and time rules are also enforced by the
verifier, but are not claims made by the parser. Structural parsing never
claims that a signature is valid.

## Deliberately pending

- independent security review, packaged lifecycle testing, accessibility, and
  production recovery/migration UX for the trusted Linux routine-rotation flow;
- adoption of older file-only roots or quarantined evidence archives into the
  live journal;
- trusted multi-party consent for threshold-policy and recovery operations;
- terminal no-successor revocation;
- independently witnessed DNS or transparency-log root/policy publication and
  freshness; and
- wallet/hardware adapters beyond what the installed OpenSSH signer supports.
