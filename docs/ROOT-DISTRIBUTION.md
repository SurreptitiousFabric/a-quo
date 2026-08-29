# Persona-root distribution and pinning

**Status:** implemented as a bounded prototype for
[issue #3](https://github.com/SurreptitiousFabric/a-quo/issues/3), not audited,
packaged, or release-ready. Accessibility properties are covered by automated
tests but still need validation with real assistive technology. This document
fixes the portable card, pin, and digest-URI meanings independently of any
particular command or operating system. It does not specify a network API.

## The trust problem

A persona root is the stable beginning of one A Quo persona history. Its
signature proves that the initial persona key signed the exact root statement.
It does not tell a new verifier whether that is the root they meant to trust.

An attacker who controls a download page can publish a different, internally
valid root proof and print that replacement root's digest beside it. Hashing
the downloaded proof again only confirms that the two attacker-supplied values
agree. It is not independent pinning.

The distribution design therefore keeps three objects separate:

1. the existing **signed root proof**, which supplies cryptographic evidence;
2. an **unsigned public root card**, derived from that proof but carrying only
   copied public root facts; and
3. an **unsigned verifier-owned pin record**, which records the digest the
   verifier chose and how they say they obtained it.

The root card may travel beside the proof, but it does not contain the proof or
an SSH signature. The pin record belongs to the verifier and should normally
travel through a different backup or migration path. Neither object contains a
private key, recovery key, signer locator, PIN, wallet credential, recovery
code, or secret share.

## Terms

- **Persona root:** the signed, immutable starting statement for one persona
  history.
- **Root-statement digest:** lowercase hexadecimal SHA-256 of the exact RFC
  8785 canonical root-statement bytes. It is not a hash of the outer proof or
  card JSON.
- **Root card:** an unsigned public copy of facts derived from one verified
  signed root proof, including its recomputed statement digest.
- **Pin:** a verifier's expected root-statement digest.
- **Pin provenance:** unsigned local metadata describing how the verifier says
  the pin was recorded and which carrier was used.
- **TOFU:** trust on first use. The first valid root seen is accepted and later
  roots must match it.
- **Same-channel comparison:** the proof and the compared digest came through
  the same administrative or delivery channel. This detects accidental
  mismatch, but not coherent substitution by that channel.
- **Out-of-band user-confirmed comparison:** the user says the digest came
  through a channel separate from the root card. A Quo records that
  declaration; it cannot prove that the channels were actually independent.

## Existing signed root proof

This design does not replace or resign the implemented
`urn:a-quo:proof:persona-root:sshsig:v1` proof. That proof contains:

- an unpadded Base64url encoding of the canonical persona-root statement;
- the normalized OpenSSH public key;
- an OpenSSH SSHSIG signature with role `root` and namespace
  `a-quo-persona-root-v1`; and
- format and schema identifiers needed to reject cross-purpose use.

The signed statement contains the self-asserted persona label, the random
persona-specific anchor, issuance time, root version, and initial-key
fingerprint. The root-statement digest is calculated from its canonical bytes.

The root proof is the cryptographic object. The root card is a portable
comparison and presentation object derived only after proof verification. A
card alone cannot be signature-verified because it contains neither the public
key nor the signature. An attacker can replace a card and the proof supplied
beside it with another valid self-created root. A separately retained pin is
what detects that substitution.

## Unsigned public root card v1

The machine-readable JSON card is RFC 8785 canonical JSON, is bounded to 4,096
bytes, and has this closed shape:

```text
schema: exactly urn:a-quo:persona-root-card:v1
canonicalization: exactly RFC8785
persona: copied self-asserted persona label
persona_anchor: copied persona-specific anchor
root_version: copied root version
issued_at: copied signed issuance claim
initial_key_fingerprint: copied canonical OpenSSH SHA-256 fingerprint
root_statement_sha256: exactly 64 lowercase hexadecimal characters
pin_uri: exact digest-only pin URI for root_statement_sha256
```

Readers reject missing, duplicate, unknown, noncanonical, or oversized input.
The card is deterministic but unsigned; its canonical bytes and optional card
digest identify the card, not the persona root. Root identity remains the
SHA-256 of the canonical signed root-statement bytes.

A verifier reconstructs the root statement from the copied card fields,
recomputes its digest, and requires both `root_statement_sha256` and `pin_uri`
to match. Signature verification still requires the separate signed root proof.
When one is supplied, every card field must equal the corresponding fact
derived from that verified proof. This prevents unsigned display fields from
drifting away from the candidate proof without pretending that the card is
itself signed.

The card is public evidence, not a credential or bearer token. Possession of
it grants no signing, recovery, wallet, or legal authority. It can be copied,
printed, archived, and verified offline.

## Digest-only QR URI

The QR payload is an exact ASCII URI with this grammar:

```text
root-pin-uri = "aquo:persona-root-pin:v1:" root-digest
root-digest = 64 lowercase hexadecimal characters
```

It carries no root proof, persona label, persona anchor, public key, issuance
time, pin provenance, URL, query, fragment, or recovery material. Uppercase
hexadecimal, percent encoding, extra whitespace, queries, and fragments are
invalid rather than normalized.

A QR scan supplies only a candidate digest for comparison. Scanning must not
silently create or replace a pin, import a root, activate a persona, open a
wallet, contact a network service, or approve any operation. The full URI and
digest must also be printed as selectable text beside the image, so the QR is
not the only accessible representation.

Because the QR contains only the root digest, the verifier still needs the
root card or signed root proof from somewhere else. If both arrive through the
same controlled page, message, or package, the comparison is same-channel and
must be reported that way.

## Verifier-owned pin record v1

The portable pin record is RFC 8785 canonical JSON, is bounded to 4,096 bytes,
and has this closed shape:

```text
schema: exactly urn:a-quo:persona-root-pin:v1
canonicalization: exactly RFC8785
root_statement_sha256: exactly 64 lowercase hexadecimal characters
recorded_at: non-negative integer Unix time no greater than 2^53 - 1
trust_basis: one of trust_on_first_use, same_channel_copy,
             out_of_band_user_confirmed
channel: one of in_person, paper, qr, voice, file, other
source_artifact_sha256: optional 64-character lowercase hexadecimal digest
```

`recorded_at` is an unsigned local observation, not a trusted timestamp.
`source_artifact_sha256`, when present, is only an opaque verifier-recorded
digest of source material such as the observed proof or card file. It does not
prove who supplied those bytes, how they travelled, or that they were
independent. A change of root digest creates a different pin decision; it must
never be disguised as an update to the old record.

The interoperable record deliberately omits the persona label and anchor. A
verifier may keep a local display name beside it, but that metadata is outside
this format and must not be treated as signed or portable identity evidence.

The record itself is unsigned. A same-user attacker who can replace it can
also roll it back or relabel its provenance. Implementations should protect it
as verifier state, export it separately from the public card, and say whether
it was newly created, loaded, or migrated. Merely finding a pin record beside
a card does not prove that they arrived independently.

### What each trust basis means

| `trust_basis` value | What happened | What it can establish | Required warning |
| --- | --- | --- | --- |
| `trust_on_first_use` | No previous pin was available; the verifier accepted the first valid root it saw | Later root substitution relative to that local first observation | First contact was not independently authenticated |
| `same_channel_copy` | A supplied digest matched the proof, but both came through the same channel or administrative control | Accidental mismatch and later change relative to the stored pin | Same-channel self-confirmation does not resist coherent channel substitution |
| `out_of_band_user_confirmed` | The user says the compared digest came through a different channel | A match against that user-selected expectation | Channel separation is user-reported, not technically established |

The `channel` value records the carrier the verifier selected. It does not
elevate the trust basis: for example, `in_person` combined with
`trust_on_first_use` still reports channel independence as not established.
`out_of_band_user_confirmed` reports only `user_reported_separate`, not
cryptographically verified independence.

No trust-basis or channel value proves legal identity, channel integrity,
trusted time, or global publication. `out_of_band_user_confirmed` is
deliberately not shortened to “independently verified” in machine output.

## Verification algorithm

An A Quo-compatible verifier need not be an A Quo binary, but it must perform
all of these steps rather than trusting displayed card fields:

1. Obtain the signed root proof separately from the unsigned card and require
   its exact proof schema.
2. Decode the proof payload as canonical unpadded Base64url and parse the
   closed v1 root-statement shape.
3. Re-encode that statement with RFC 8785 and require byte-for-byte equality
   with the decoded payload.
4. Require signature role `root`, format `sshsig`, public-key format
   `openssh-public-key`, and namespace `a-quo-persona-root-v1`.
5. Normalize the embedded OpenSSH public key, calculate its canonical OpenSSH
   SHA-256 fingerprint, and match the statement's initial-key fingerprint.
6. Verify the SSHSIG over the canonical payload under the exact root
   namespace.
7. Calculate lowercase hexadecimal SHA-256 over those canonical payload bytes.
8. If a card is supplied, parse its bounded canonical JSON, reconstruct the
   statement from its copied fields, and require the complete card to match the
   card deterministically derived from the verified proof—including its digest
   and pin URI.
9. Parse the verifier pin separately and compare its digest with the verified
   proof's digest.
10. Compare any QR/input digest with the same verified digest, keeping its
    provenance separate from signature validity.
11. Report root proof validity, card consistency, pin relation, provenance,
    timing warnings, and current-history status as separate results.

Generic tooling can decode JSON/Base64url, apply RFC 8785, calculate SHA-256,
and use OpenSSH SSHSIG verification. An OpenSSH-based implementation can place
the embedded public key under a fixed local allowed-signers identity and use
`ssh-keygen -Y verify` with namespace `a-quo-persona-root-v1`, reading the
canonical payload on standard input. The allowed-signers identity is local
bookkeeping; it is not a legal identity claim.

A compatible verifier must also enforce A Quo's algorithm profile: Ed25519,
ECDSA P-256/P-384/P-521, OpenSSH FIDO Ed25519/P-256, or RSA with RSA-SHA2 and a
2,048 through 4,096-bit modulus. DSA, RSA-SHA1, unknown algorithms, and RSA
outside that size range fail closed. A generic OpenSSH success result without
the schema, canonicalization, role, namespace, fingerprint, algorithm-profile,
card, and pin checks is not an A Quo root-distribution verification. A root
card alone can be checked for internal consistency, but its root signature
status remains `not_checked`.

## First contact and later comparison

### TOFU first contact

1. Obtain a signed root proof and, optionally, its public root card.
2. Verify the proof, derive the candidate card, and compare any supplied card.
3. Show the self-asserted persona label, full root digest, initial-key
   fingerprint, signed issuance time, and the absence of an existing pin.
4. If the user explicitly accepts first-use trust, write a verifier-owned pin
   with trust basis `trust_on_first_use` and the selected channel.
5. Warn that an attacker controlling this first delivery could have supplied a
   coherent replacement root.

TOFU is useful continuity from this point forward. It is not retroactive proof
of who controlled the persona before first contact.

### Same-channel comparison

If a root card and its digest or QR came from the same website, repository,
message thread, package, administrator, or synchronized account, record
`same_channel_copy`. A match is still useful for catching copying mistakes,
but the verifier must show that the channel could have replaced both values
together.

Copying the digest out of the card, proof, or a verification result produced
from that same card is always same-channel self-confirmation. It must never be
upgraded to out-of-band provenance.

### Out-of-band user-confirmed comparison

1. Obtain the root card or signed proof through one path.
2. Obtain the digest-only QR URI or full textual digest through a path the user
   considers separate.
3. Verify the proof and recompute its digest before comparison.
4. Require an exact digest match.
5. Record `out_of_band_user_confirmed` only after the user explicitly selects
   that trust basis and one of the closed channel values.
6. Report that the separate-channel claim is user-reported, not technically
   proved by A Quo.

Examples of potentially separate paths include an in-person printout, a voice
comparison, or a previously retained verifier record. Whether two paths are
actually independent depends on their operators, accounts, devices, and
failure modes; A Quo does not decide that automatically.

### Re-verification

For every later candidate:

1. verify the root proof again;
2. recompute the root digest;
3. derive and compare any supplied card; and
4. compare the verified root digest with the unchanged stored pin at an
   explicitly recorded comparison time.

Re-verification is read-only with respect to the pin record. If the verifier
deliberately obtains and records a new pin observation, it creates a new
no-overwrite record and retains the original rather than rewriting the first
observation as mutable history.

A mismatch is a hard conflict. The verifier must retain the old pin, display
both full digests, and require an explicit new-persona decision rather than
offering “trust latest” or silent repinning. A persona root does not rotate; a
different root starts a different persona history even if it uses the same
label.

## Time and current-history warnings

A persona root has no expiry field and does not expire merely because time
passes. Its signature is historical evidence that the initial key signed that
root statement. Implementations must not invent a root expiry date.

The signed `issued_at` is the root's claimed issuance time, not a trusted
timestamp. The pin's `recorded_at` and the comparison's `checked_at` are
unsigned local observations. Reports keep them separate. If a local time
appears to precede the signed issuance claim, report a clock-relation warning;
do not reject the root or infer which clock was correct.

Two warnings replace the misleading idea of an “expired root”:

- **Late first contact:** for a matching pin whose unsigned `recorded_at` is
  not earlier than signed `issued_at`, display their gap.
  `late_first_contact` becomes true only when that gap is greater than 30 days.
  This is a UX warning, not expiry, trusted time, or evidence that the root was
  safe before observation.
- **Pin observation review due:** display the age of `recorded_at` at the
  comparison time. `pin_observation_review_due` becomes true only when that
  age is greater than 365 days. It requests review; it does not invalidate the
  root or pin.
- **Current history not checked:** a valid matching root identifies the
  history's beginning, not its current key, latest policy, latest transition,
  terminal status, or absence of a withheld branch. Until those are checked
  through separately supplied continuity evidence and expectations, report
  them as not established.

A “stale root” test therefore expects a valid historical root plus a
current-history warning, not signature rejection based on age.

## Required result language

Machine and human reports keep at least these dimensions separate:

- root signature: valid or invalid;
- supplied card: not checked, matched, or mismatched against the card derived
  from the verified proof;
- verifier pin: matched or mismatched;
- trust basis: `trust_on_first_use`, `same_channel_copy`, or
  `out_of_band_user_confirmed`;
- trust-basis source and selected channel, reported separately;
- channel independence: `not_established` or `user_reported_separate`;
- provenance assurance: `user_recorded_not_cryptographically_verified`;
- root timing: signed issuance, unsigned pin observation and comparison times,
  first-contact delay, pin age, and their warning flags;
- current history: not checked, checked to a named checkpoint, or conflict;
- legal or government identity: not established;
- current signing or recovery authority: not established by the card;
- artifact truth or safety: not established; and
- root-card possession: no authority granted.

There is no single green “trusted identity” result. A verified signature, a
matching card digest, and an out-of-band declaration answer different
questions.

## Accessible renderings

The JSON card and pin record are the portable machine formats. Text and print
HTML are accessible public renderings derived from a successfully verified
root. Pin inspection and comparison reports are separate because a publisher
card must not absorb verifier-owned provenance.

### Text

The text rendering must:

- use headings and labels rather than alignment or color;
- print the full root digest and initial-key fingerprint without truncation;
- label the persona name as self-asserted;
- state that the root is self-asserted, the QR is a comparison convenience,
  and an independent pin source is not established by the card;
- include all warnings and non-claims in ordinary selectable text; and
- remain understandable when copied into a plain terminal, email, or document.

### Print HTML

The print rendering must be a self-contained static document with no scripts,
remote fonts, remote images, tracking, automatic navigation, wallet hand-off,
or network fetch. It must:

- use semantic headings, lists, and definition markup;
- remain usable with CSS disabled and at enlarged text sizes;
- use high contrast and never rely on color alone;
- put the full digest-only URI in text beside any QR image;
- include the signed issuance time with a clear label; and
- repeat that the card does not establish legal identity, current authority,
  channel independence, or safety.

The specified print HTML is the public card only. It must not include or
require the pin record, trust basis, channel, `recorded_at`, or comparison
time. If a user creates a separate combined printout, placing a card and pin
provenance together does not make their original channels independent. Any
public printout also increases correlation exposure.

## Loss, migration, and channel compromise

| Situation | Safe action | What cannot be recovered or claimed |
| --- | --- | --- |
| A Quo binary or original operating system is unavailable | Verify the signed root proof with generic JSON, RFC 8785, SHA-256, and OpenSSH SSHSIG tooling, then compare the separately retained card and pin; preserve all three as ordinary files | Generic signature verification alone does not supply pin provenance or current history |
| Root card is lost but the signed root proof remains | Reverify the proof and regenerate an equivalent unsigned card | The old card's delivery path is not reconstructed |
| Signed proof is lost but a root card remains | Reacquire the exact signed proof, verify it, and require its derived card to match the retained card | The card contains no public key or signature, so it cannot reconstruct or signature-verify the proof |
| Pin record is lost | Re-establish trust explicitly as new TOFU or through a new `out_of_band_user_confirmed` observation | The previous `recorded_at`, trust basis, channel, and optional source digest cannot be recreated from the card; hashing it is not recovery of independent trust |
| Device or verifier migration | Transfer the card and verifier pin record as separate ordinary files, preserve the pin record's original fields, reverify before use, and record migration only as local application metadata | Migration does not upgrade provenance or prove the new device trustworthy |
| Routine signing key is lost | Keep using the same root as the historical anchor and evaluate an authorized recovery transition under the separately pinned policy and head | The root card does not recover or reconstruct the lost key |
| Distribution channel is compromised | Compare against a previously retained verifier pin or a digest obtained through a user-reported separate path; reject a changed root | A replacement proof and replacement digest from the same compromised channel can self-confirm |
| Local verifier state is coherently rolled back | Compare with another retained pin record or independently witnessed current-history checkpoint | The unsigned local pin record is not a transparency log or trusted timestamp |

Recovery must never require one wallet vendor, Linux desktop, A Quo daemon, or
online service. The portable objects are ordinary public JSON/text, and the
signature profile is OpenSSH SSHSIG. Platform-specific applications may make
the workflow easier but must not change the evidence meaning.

## Correlation and disclosure

| Object or rendering | Public information exposed | Correlation consequence |
| --- | --- | --- |
| Signed root proof | Self-asserted persona label, persona anchor, initial public key and fingerprint, signed issuance claim, root digest | Copies can be linked to the same persona history; publishing the anchor is intentionally correlating |
| JSON root card | Copied self-asserted label, anchor, root version, issuance claim, initial-key fingerprint, root digest, and pin URI | It exposes the same stable persona-history link without containing the public key or signature |
| Text or print HTML | The same verified root fields plus human-readable status and warnings | Searchable or photographed copies may make correlation easier |
| Digest-only QR URI | One stable root digest plus fixed type/algorithm text | Scans of the same digest can be linked, but the QR omits the label, anchor, key, and proof |
| Verifier-owned pin record | Root digest, trust basis, selected channel, unsigned `recorded_at`, and optional source-artifact digest | Exporting or synchronizing it reveals that this verifier tracks that root and when it says it recorded it |
| Continuity history distributed with the root | Later key, policy, recovery, or terminal statements | Reveals a larger timeline and relationships among keys within the persona |

Do not combine root cards or pin records from separate personas into a public
index unless that correlation is intentional. No global A Quo identifier is
introduced by this format.

## Public vectors and negative-test coverage

The bounded prototype includes immutable public positive vectors without
inventing a second root-proof format. The vector set contains:

- one existing-format signed persona-root proof whose payload is decoded and
  checked as the canonical statement by the portable fixture test;
- the corresponding v1 root card and independently recomputed statement
  digest;
- the exact digest-only QR URI bytes;
- one pin record for each trust-basis value, with the closed channel values
  covered across the set;
- expected machine-report semantics and hashes of the accessible text/print
  renderings; and
- explicit component schema identifiers and provenance notes saying which
  observations are simulated.

Hostile cases are generated independently in unit and end-to-end tests rather
than checked in as misleadingly reusable “bad proofs.” Together those tests
must mutate or substitute:

- the card digest, proof schema, payload, root-statement field,
  canonicalization, signature, role, namespace, public key, and key
  fingerprint;
- QR prefix, algorithm, digest length/case, whitespace, query, and fragment;
- stored pin digest, canonicalization, trust basis, channel, recorded time, and
  optional source-artifact digest;
- comparison/issuance/recorded-time relations and both strict UX-warning
  boundaries; and
- a valid but different root proof paired with its own matching derived card.

The last case is essential: it must pass internal signature/card checks and
still conflict with the verifier's pre-existing pin. Warning vectors must
cover `trust_on_first_use`, `same_channel_copy`,
`out_of_band_user_confirmed`, `user_reported_separate`, late first contact,
pin-observation review due, local-clock relation, and a valid old root with
current history not checked.

The vector manifest names its component schemas, expected result classes, and
generation revision. The fixture README gives the generic OpenSSH verification
procedure. Test keys or generation inputs must never be confused with real
persona or recovery credentials.

## Deliberate non-claims and exclusions

Root-card verification does not establish:

- legal, government, or wallet identity;
- that the self-asserted persona label belongs to a particular human;
- current signing or recovery authority;
- current non-revocation, latest history, or absence of a withheld fork;
- trusted issuance, pin-recorded, or comparison time;
- that two delivery channels were independent;
- truth, originality, copyright ownership, code review, or artifact safety;
- control of a domain or social account; or
- possession of any private or recovery key.

The design uses no D-Bus authority, credential wallet, network lookup,
blockchain, transparency service, or automatic publication. Those may later
supply separate evidence, but they do not change the root card or silently
upgrade a pin's provenance.
