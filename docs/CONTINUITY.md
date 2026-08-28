# Portable persona continuity v1

## Status and meaning

A Quo implements portable proofs for routine key handoff and threshold recovery.
A routine transition is signed by both the old and new keys. A recovery
transition is signed by the configured threshold of recovery-only keys and by
the proposed new online key.

It is not legal identity, key non-revocation, or proof that the root or latest
recovery policy was trusted at a useful time. A verifier must obtain the
expected root-statement SHA-256 through a separate trusted channel. Copying the
digest out of the same untrusted proof collection is a consistency check, not
independent pinning.

On Linux, `root-request` sends the exact canonical root statement through the
private daemon and requires a root-specific direct-Wayland approval before the
registered active key signs. The daemon reviews persona, key, canonical bytes,
and a five-minute clock window both before consent and immediately before
signing. The client then verifies the sealed result again before creating the
output file. This establishes trusted **local consent to that exact statement**;
it does not establish that another verifier obtained or pinned the root digest.

`root-create`, transition creation, recovery-policy management, and recovery
transition creation remain low-level commands that invoke key paths directly.
Trusted multi-key consent is still pending.

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

`transition-verify` establishes two valid signatures over one statement but
does not claim that the statement belongs to a trusted root or ordered chain.
`chain-verify` additionally checks every link and the caller-supplied expected
root digest. Its report still lists root-pin timing/source, legal identity,
current authorization/non-revocation, recovery authority, and artifact safety
as not established.

Proof inputs are bounded, must be regular files, and are opened without
following symlinks on Linux. New proof outputs use mode 0600 on Unix, are synced,
and never overwrite an existing path. Proof contents are public verification
material but correlate the selected persona.

The Linux root request uses its own closed IPC message and a sealed descriptor;
it cannot be confused with artifact, domain-control, or transition signing.
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

- trusted two-key transition consent prompts;
- atomic coordination with the local persona/key lifecycle store;
- trusted multi-party consent for threshold-policy and recovery operations;
- independently witnessed DNS or transparency-log root/policy publication and
  freshness; and
- wallet/hardware adapters beyond what the installed OpenSSH signer supports.
