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

On Linux, `root-request` sends the exact canonical root statement through the
private daemon and requires a root-specific direct-Wayland approval before the
registered active key signs. The daemon reviews persona, key, canonical bytes,
and a five-minute clock window both before consent and immediately before
signing. It records the verified root in the local schema-v3 continuity journal
before returning a sealed proof. The client verifies both the result and its
journal entry before creating the output file. An identical retry exports the
recorded proof; a different existing output is never overwritten.

For a newly journaled, routine-only history, Linux `transition-request` provides
trusted local two-key consent and atomic lifecycle coordination. The caller must
supply `--expected-root-sha256`; the local journal can require that it matches,
but cannot prove that the caller obtained it independently. The trusted prompt
shows the persona and anchor, purpose, sequence and issuance time, pinned root,
previous chain head, old and new key fingerprints, exact transition-statement
digest, request identifier, and caller credentials.

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
adopt older roots that exist only as files or histories that already contain a
recovery transition. `root-create`, `transition-create`, recovery-policy
management, and recovery-transition creation remain low-level commands that
invoke key paths directly. In particular, `transition-create` produces valid
portable two-key evidence but does not provide the daemon's trusted review,
journal, or atomic key-transfer guarantees. Trusted multi-party recovery
consent is still pending. Until that recovery path is integrated with the
journal, the local lifecycle command also refuses to mark its current head
compromised out of band; earlier retired keys can still be marked.

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

The local schema-v3 journal is separate from the portable v1 proof format. Its
root is immutable, its accepted transition rows are append-only, and every
routine-journal snapshot used by the trusted path reverifies the stored root,
transitions, and claimed head. Once a persona has a journaled root, ordinary
local key-add and key-rotation operations cannot bypass the proof-authorized
routine rotation path. The journal is still user-owned SQLite state, not a
remotely witnessed or tamper-proof ledger.

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
  --expected-root-sha256 DIGEST_FROM_SEPARATE_TRUSTED_CHANNEL

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

a-quo continuity recovery-chain-verify --root ROOT_PROOF \
  --policy POLICY_PROOF ... --transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 POLICY_PIN
```

`root-request` and `transition-request` are the trusted Linux journal flows and
require the private daemon plus packaged consent helper. `--next-provider` is
closed to `openssh-file`, `ssh-agent`, or `fido2`. The proposed public key is
passed as a bounded descriptor; the daemon constructs the statement from its
authoritative journal rather than accepting caller-authored transition bytes.
The signing key or SSH-agent/FIDO stub named by `--next-key` must match
`--next-public-key` and the selected provider.

`transition-verify` establishes two valid signatures over one statement but
does not claim that the statement belongs to a trusted root or ordered chain.
`chain-verify` additionally checks every link and the caller-supplied expected
root digest. Its report still lists root-pin timing/source, legal identity,
current authorization/non-revocation, recovery authority, and artifact safety
as not established.

Proof inputs are bounded, must be regular files, and are opened without
following symlinks on Linux. New proof outputs use mode 0600 on Unix and are
file-synced; on Linux the atomic writer also syncs the destination directory.
Journal-flow retries accept an existing output only when it is the exact
recorded proof; other outputs are never overwritten. Proof contents are public
verification material but correlate the selected persona.

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
4,096 transitions.

## Deliberately pending

- independent security review, packaged lifecycle testing, accessibility, and
  production recovery/migration UX for the trusted Linux routine-rotation flow;
- adoption of older file-only roots and recovery-containing histories into the
  local routine journal;
- trusted multi-party consent for threshold-policy and recovery operations;
- independently witnessed DNS or transparency-log root/policy publication and
  freshness; and
- wallet/hardware adapters beyond what the installed OpenSSH signer supports.
