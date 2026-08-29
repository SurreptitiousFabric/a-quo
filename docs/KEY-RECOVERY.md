# Persona continuity, backup, and recovery

**Status:** metadata-only backup v1, the evidence-only backup v2 foundation,
portable persona roots, trusted single-key Linux root consent, dual-signed
routine continuity, and threshold recovery are implemented as bounded
prototypes. A v2 import can preserve and reverify supplied public continuity
evidence, but it remains quarantined from operational signing and recovery.
Trusted multi-key consent, live recovery commit/adoption, and a journaled
revocation workflow remain release work.

## Three different operations

A Quo must not call every replacement key “recovery.” These operations carry
different evidence:

| Operation | Required authority | What it can establish |
| --- | --- | --- |
| Metadata restore (v1) | a user-selected local backup | Recreates non-secret local labels, public keys, statuses, and history; establishes no cryptographic continuity |
| Evidence restore (v2) | a user-selected local backup containing public proofs | Preserves and internally reverifies the signed history that was supplied; establishes neither its freshness nor operational authority |
| Routine rotation | previous signing key **and** new signing key | Both key holders approved the next signing key for this persona |
| Recovery | threshold of previously authorized offline recovery keys **and** new signing key | The pinned recovery policy authorized replacing an unavailable or compromised signing key |

Possession of an exported file is never authority to sign. A valid recovery
signature does not prove legal identity, and it cannot rescind historical facts
signed by an older key.

## Persona-specific trust anchor

Recovery requires an explicit public continuity identifier. When a user opts
in, A Quo will generate a random 256-bit `persona_anchor` for that persona. It
is never shared across personas and is not derived from a legal identity,
device, wallet, account, or global A Quo identifier.

Publishing an anchor intentionally makes events within that one persona
correlatable. The ordinary artifact proof remains unchanged and does not expose
the local persona UUID or an anchor unless the user separately chooses a
continuity proof.

An initial policy is self-asserted until a verifier pins it through a trusted
out-of-band exchange or observes it through separately verified evidence such
as a DNSSEC domain proof or transparency-log inclusion. A policy created after
a signing-key compromise cannot retroactively prove that the attacker was not
the party who created it.

## Signed recovery policy

The implemented versioned policy statement contains only public data:

- statement schema and canonicalization identifier;
- persona anchor and self-asserted persona label;
- monotonically increasing policy version;
- digest of the previous policy, except at version 1;
- exact continuity checkpoint sequence and transition digest;
- bounded set of recovery public keys and their fingerprints;
- threshold of distinct recovery keys required;
- issuance and expiry times; and
- no private key, signer path, wallet credential, PIN, or recovery code.

Policy payloads use RFC 8785 JSON Canonicalization Scheme bytes and a distinct
OpenSSH SSHSIG namespace. OpenSSH defines namespaces specifically to prevent a
signature made for one interpretation domain from being accepted in another.
Every listed recovery key must prove possession when the initial policy is
created; merely naming somebody else's public key is insufficient.

Policy version `N+1` must be authorized by the threshold in trusted version `N`
and by the threshold declared in version `N+1`. Versions cannot be skipped or
rolled back. Each fingerprint counts at most once toward a threshold. This
follows the conservative root-update shape used by The Update Framework rather
than treating one mutable database row as a root of trust.

Every policy also signs an exact continuity checkpoint. A recovery authorized
by policy `N` must be after that policy's checkpoint. Once policy `N+1` exists,
an older-policy recovery is accepted only if it is at or before `N+1`'s
checkpoint, which means both the old and new authority sets ratified that exact
history prefix. This preserves valid historical recovery while preventing a
superseded authority set from authorizing another transition. A policy-only
verification can validate policy signatures but explicitly reports that it did
not receive the transition chain needed to validate the checkpoint.

## Signing-key transitions

The implemented routine-transition v1 statement binds:

- the persona anchor and exact persona-root statement digest;
- the exact previous and next public keys/fingerprints;
- the next transition sequence number;
- a closed reason and bounded time; and
- the digest of the previous transition, when one exists.

It requires distinct valid signatures from both the previous and next signing
keys. The second signature proves custody of the proposed key and prevents a
mistyped or substituted public key from becoming authoritative.

The implemented recovery transition uses a separate policy-bound schema. It
binds the exact recovery-policy digest and replaces the previous-key signature
with the configured threshold of distinct recovery-key signatures. It still
requires the next signing key to sign. A compromised or retired online signing
key cannot approve a recovery transition by itself.

All policy and transition signatures use separate SSHSIG namespaces from
artifacts, DNS domain control, and each other. Inputs, signature arrays, key
counts, text fields, and validity periods are hard-bounded. A policy contains
2–32 recovery authorities, a supplied policy chain contains at most 1,024
versions, and one policy is valid for at most 315,576,000 seconds (ten Julian
years). Duplicate keys, duplicate signatures, unknown fields, noncanonical
encodings, rollback, gaps, and mismatched fingerprints fail closed.
Mixed-chain verification also rejects a recovery authority fingerprint that
appears anywhere as an online persona key in the supplied continuity history.

The low-level CLI surface is:

```text
a-quo continuity recovery-policy-create --root ROOT_PROOF \
  [--prior-transition ROUTINE_PROOF ...] \
  --threshold M --valid-days DAYS \
  --authority-key KEY --authority-public-key KEY.pub ... \
  --output POLICY_V1_PROOF

a-quo continuity recovery-policy-update --root ROOT_PROOF \
  --policy POLICY_PROOF ... --transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 CURRENT_POLICY_PIN \
  --threshold M --valid-days DAYS \
  --previous-authority-key KEY --previous-authority-public-key KEY.pub ... \
  --current-authority-key KEY --current-authority-public-key KEY.pub ... \
  --output NEXT_POLICY_PROOF

a-quo continuity recovery-transition-create --root ROOT_PROOF \
  --policy POLICY_PROOF ... --prior-transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 LATEST_POLICY_PIN \
  --reason recovery --authority-key KEY --authority-public-key KEY.pub ... \
  --next-key NEW_KEY --next-public-key NEW_KEY.pub --output TRANSITION_PROOF

a-quo continuity recovery-chain-verify --root ROOT_PROOF \
  --policy POLICY_PROOF ... --transition TRANSITION_PROOF ... \
  --expected-root-sha256 ROOT_PIN --expected-policy-sha256 LATEST_POLICY_PIN \
  [--expected-head-sequence N --expected-head-sha256 HEAD_PIN]
```

Each repeated proof is supplied in sequence/version order. Policy creation
requires every initially listed key to prove possession. Updates require the
old threshold and proof of possession from every key listed in the new policy;
verification enforces at least the thresholds. Signing is currently sequential
on one host, so it is not yet a trusted distributed ceremony.

The low-level continuity commands reject excess path counts before opening any
supplied input or starting signature verification: at most 4,096 transitions,
1,024 recovery-policy versions, and 32 recovery authority key pairs. Within
those count ceilings, one command may read at most 64 MiB of aggregate raw proof
and public-key input, with the existing 1 MiB per-proof and 16 KiB per-public-key
limits still enforced. The 64 MiB command budget is deliberately separate from
the tighter 4 MiB portable-backup limit; it accommodates thousands of ordinary
compact proofs without allowing the independent count and per-file ceilings to
compose into multi-gigabyte input.

One low-level command may perform at most 2,048 actual SSHSIG signature
verifications, including repeated prior/result chain passes made by creation or
update commands. A count-derived minimum-work check runs before file I/O. Once
all inputs have passed closed structural parsing, their exact signature counts
are charged before the first verifier runs. The command fails rather than
truncating history. This limit is independent of the portable-backup archive's
own 2,048-verification cap.

These simultaneous ceilings are operational resource controls, not
protocol-validity claims; staying below them does not make evidence valid, and
exceeding an aggregate CLI budget does not by itself make otherwise portable
proof bytes cryptographically invalid. The low-level ceiling is separate from
selected live-journal work. Live routine journals now enforce a 64 MiB
aggregate proof-byte preflight and use a single native verification pass: a
maximum 4,096-transition chain requires 8,193 in-process signature checks, with
each stored proof checked once. An append at an already verified tip checks only
its two candidate signatures and retains an opaque receipt. The append reserves
the candidate's serialized bytes against the 64 MiB total, then reverifies the
stored prefix under the immediate writer transaction and links the receipt to
that exact head without repeating the candidate checks. Daemon, CLI, and
Omarchy security checkpoints can still revalidate separately; safe
cross-transaction reuse of the stored-prefix result and a request-wide
crypto-work budget remain hardening work.

## Portable persona backups

### Metadata-only v1

The first implementation slice is a versioned JSON backup for one persona. It
contains the local persona record, OpenSSH public keys, lifecycle states, and
append-oriented event history. Existing v1 files remain accepted by inspection
and import. V1 deliberately excludes:

- private keys and hardware-key stubs;
- signer paths and SSH-agent configuration;
- recovery secrets, PINs, and wallet material;
- official Swiss/EU credentials;
- the continuity root, transition proofs, and journal head introduced in
  schema v3; and
- any claim that the backup is a signed continuity proof.

V1 parsing is limited to 4 MiB, 256 public keys, and 4,096 lifecycle events. The
production byte parser rejects larger inputs before JSON deserialization; typed
validation then enforces the count and field limits. Import validates every
public-key fingerprint, provider, status/time relationship, event reference,
field bound, and persona UUID before one atomic transaction. It refuses
collisions and never restores signer paths. For active, unarchived v1 metadata,
the owner must explicitly bind a currently available signer afterward;
archived v1 metadata remains non-operational and cannot be rebound.

The JSON schema and standard OpenSSH public-key text are portable across A Quo
platform adapters. The file is sensitive because it can correlate a persona's
history even though it contains no signing secret. Users should protect and
delete copies according to their privacy needs.

Restoring v1 metadata does not recreate a continuity-managed persona or its
portable journal. Users must preserve public root/transition proof files and
independently obtained checkpoints separately.

The v1 backup is deliberately unsigned. Validation detects
malformed data, fingerprint substitution, and internally inconsistent history;
it cannot distinguish a coherent rewrite by someone who can replace the whole
file. A backup must therefore be treated as user-supplied metadata, never as a
trust root or portable proof shown to somebody else.

### Evidence-only v2 foundation

V2 adds a required closed continuity discriminator. An `unmanaged` backup
retains metadata-only meaning. An `evidence_archive` carries a self-contained
public persona-root proof, an ordered recovery-policy proof chain, and an
ordered, explicitly tagged mixed chain of routine and recovery transition
proofs. Each proof may also retain a local `observed_at` value. Inspection and
import reverify the supplied root, policy signatures and thresholds, policy
versions and transition checkpoints, transition signatures and links,
persona/root/key bindings, and lifecycle replay. A successful v2 import
preserves that evidence so a later export can carry it again.

The resulting records are quarantined evidence. Import does not install the
history as the live continuity journal, select a current signer, bind a signer
locator, authorize a recovery, or make a compromised key usable. Private keys,
hardware-key stubs, current or historical signer locators, SSH-agent
configuration, recovery secrets, PINs, wallet material, and official
credentials remain excluded. An owner must use a separate, explicit future
adoption workflow before imported evidence can affect operational signing or
recovery.

V2 serializes neither an operational journal head nor a local journal revision.
The chain tip is recomputed from the verified proof sequence. It is still only
the tip of the history supplied in this backup.

The quarantine is enforced by operational behavior, not only by report text.
An evidence-archive persona cannot use ordinary key enrollment or rotation,
signer binding or selection, or out-of-band compromise of its supplied chain
tip. Its keys are reported as evidence-only rather than active local authority;
they cannot authorize `sign --persona-id`, consent-mediated signing, or an
Omarchy plugin installation or update. Those operations require the planned
live adoption, recovery-commit, and revocation workflows rather than silently
treating imported evidence as the authoritative journal.

Every embedded digest and the chain tip derived from the backup came from the
same untrusted package. They are useful for internal linkage, but they are not
independently obtained root, latest-policy, or continuity-head pins. A valid
self-contained backup can therefore be a coherent older prefix or one fully
authorized sibling branch. Inspection and import do not establish that a newer
policy, transition, compromise record, or competing branch was not withheld;
that signed issuance/expiry times or unsigned `observed_at`/`exported_at` values
are trusted; or that the chain-tip key is currently authorized and non-revoked.
Safe comparison against independently held checkpoints, fork handling, and
live recovery-aware adoption remain separate product work.

V2 is closed and bounded. Unknown backup versions, unknown fields or proof
variants, malformed canonical payloads, duplicate or out-of-order policy and
transition proofs, cross-persona splices, persona-wide lifecycle time
regression, mismatched lifecycle state, and any limit violation fail before
persistent state changes. The aggregate compact JSON is limited to 4 MiB, as
for v1. Both parsing and export additionally enforce at most 256 public keys,
4,096 lifecycle events, 256 recovery-policy proofs, 256 transition proofs,
2,048 signature-verification work units, and 1 MiB per embedded proof. Root
and recovery-policy signatures count once for digest derivation and again for
full-chain verification under the current two-pass verifier. This work budget
is enforced together with the proof formats' per-policy authority and
signature limits. These are
simultaneous ceilings, not a promise that every combination of maxima fits
under 4 MiB. Structural and aggregate-count checks complete before signature
verification begins. Export never silently drops an older event or proof to
meet a limit: it either emits the complete supported history or fails without
replacing an existing output. Successful exports are new mode-0600 files on
Unix; existing paths are never overwritten.

The production backup parser and lifecycle replay validator are exercised by a
coverage-guided target with synthetic active, rotation, recovery, compromise,
and hostile-field seeds. Successful inputs must serialize, parse, and validate
to the same typed backup. Failures must remain bounded printable ASCII. The
bounded campaign is useful hardening evidence, not proof that every possible
input has been tested.

The implemented CLI surface is:

```text
a-quo persona backup-export --persona-id PERSONA_ID \
  [--root ROOT_PROOF \
   --recovery-policy POLICY_PROOF ... \
   --transition ROUTINE_OR_RECOVERY_PROOF ...] \
  --output NEW_FILE
a-quo persona backup-inspect FILE
a-quo persona backup-import FILE
```

Export emits v2. With no continuity proof inputs it preserves the persona's
existing state: a live routine journal or previously imported archive is
exported as an `evidence_archive`, while a persona with no continuity state uses
the closed `unmanaged` form. Supplying external evidence requires a root;
policy and transition proofs are repeated in their version/sequence order and
may be attached only when the persona has no existing live or archived
continuity. Existing v1 files remain inspectable and importable but are not
rewritten in place.

Inspection validates without opening a persona store. Import validates before
opening its destination store, then refuses persona-ID and key-fingerprint
collisions and writes all restored records in one database transaction. An
opaque verification token immutably borrows the exact backup from the
pre-open cryptographic check through the transactional import, avoiding both a
second signature pass and mutation between verification and use. V2 proof
evidence is stored as quarantined evidence; it is not copied into operational
signer references or a live recovery journal.

The machine-readable report keeps the evidence dimensions separate.
`metadata_consistency`, `root_signature`, `transition_chain`,
`recovery_policy_chain`, and `policy_transition_checkpoints` report only the
checks actually performed; an absent dimension is not promoted to verified.
For an evidence archive, `persona_label_binding=verified` means the signed root
label exactly matches the backup label. Persona UUID, purpose, and lifecycle
timestamps remain `unsigned_local_metadata`; v1 and unmanaged v2 also report
the persona label as unsigned metadata.
The backup commands accept no independent pin, so `external_root_pin`,
`external_head_pin`, and `external_latest_policy_pin` report `not_checked`, and
`current_authorization_or_non_revocation` reports `not_established`. Import of
an evidence archive reports `disposition: evidence_only_quarantined`,
`signer_references_restored: 0`, and `signing_authority: false`.

For an archive with recovery policies, `latest_policy_time_status` is evaluated
at `checked_at`: the verifier's current local clock for CLI inspection/import,
or the explicit verifier-observed time supplied to the lower-level library
helper. It is deliberately separate from the backup's unsigned `exported_at`
and proof-entry `observed_at` values. This reports policy-time evaluation at the
chosen verifier time; it is not a trusted timestamp or evidence of archive
freshness or current non-revocation.

The report's `not_established` array makes the remaining exclusions exact. It
always includes `when_or_how_the_root_was_pinned`,
`whether_a_newer_or_competing_transition_was_withheld`,
`independent_head_checkpoint_not_checked`,
`current_online_key_non_revocation`, `signing_or_recovery_authority`,
`trusted_time_for_signed_issuance_or_archive_export`,
`archive_freshness_completeness_or_authorship_as_a_whole`,
`exact_correspondence_between_unsigned_lifecycle_events_and_signed_transitions`,
`legal_or_government_identity`, `current_signer_custody`, and
`artifact_or_software_safety`. When policies are present it also includes
`when_or_how_the_latest_recovery_policy_was_pinned` and
`whether_a_newer_or_competing_recovery_policy_was_withheld`.

## Verification language

Verifiers report these dimensions independently:

- backup parsed and internally consistent;
- supplied signed root, policy, and mixed transition history internally verified;
- an independent root, latest-policy, or head checkpoint supplied and matched;
- policy signatures and threshold valid;
- policy pinned or witnessed before the relevant compromise;
- transition signatures and sequence valid;
- old/new/recovery key lifecycle state in the selected trust source;
- signer availability and current authorization/non-revocation; and
- current artifact signature valid.

No single green “identity recovered” result collapses those facts. If the
policy was not pinned before compromise, A Quo must say so. Historical artifact
proofs remain inspectable after rotation or recovery and are never rewritten.

## Implementation order

1. the original strict non-secret metadata-only v1 format, with inspection and
   import compatibility and no signing authority (implemented and retained);
2. bounded evidence-only v2 preservation and internal reverification of a
   supplied root, policy chain, and mixed transition chain (foundation
   implemented; quarantine-to-live adoption, external checkpoint comparison,
   and fork handling remain);
3. persona anchor, trusted single-key Linux root consent, dual-signed routine
   continuity statements, and trusted two-key Linux transition consent for
   newly journaled routine-only histories (prototype implemented; hardening,
   packaging, and older-history adoption remain);
4. threshold recovery policy creation, rotation, exact continuity checkpoints,
   and recovery transitions (protocol/low-level CLI prototype implemented);
5. trusted multi-key consent ceremonies plus journaled recovery commit,
   current-head compromise/revocation, and explicit evidence adoption;
6. optional, separately verified transparency-log and DNS anchoring adapters.

## Standards rationale

- [OpenSSH SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
  supplies detached signatures and explicit interpretation namespaces.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) supplies an interoperable
  canonical JSON representation rather than relying on one language's struct
  field order.
- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/)
  supplies the old-threshold plus new-threshold, exact-next-version model for
  changing high-value root keys.
- [Sigstore's security model](https://docs.sigstore.dev/about/security/)
  explains why append-only public evidence still needs inclusion verification
  and monitoring; a log is an evidence source, not magical recovery authority.
