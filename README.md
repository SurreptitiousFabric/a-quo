# A Quo

**A Quo helps you show which persona signed a digital artifact, or what a
specific credential presentation proves—and no more than the evidence says.**

You can create a persona of your own, sign files with it, preserve that
persona as signing keys change, and let somebody verify the evidence later.
A Quo is also designed to accept specific claims from external credential
wallets while those wallets keep the credentials and private keys. Signed
Omarchy plugins are the first concrete use case, not the whole product.

> **Signed does not mean safe.** A signature can show that exact bytes were
> signed by a key. It cannot, by itself, show that the bytes are harmless,
> true, original, reviewed, or connected to a legal identity.

This repository is an early, security-conscious prototype. Its proof model is
portable beyond Omarchy, but several trusted interactions and isolated
verifiers are currently Linux-specific, and release packaging is unfinished.

The product is **A Quo**. The repository and command are `a-quo`; the Omarchy
plugin identifier is `a-quo.identity`.

## The point

Files, screenshots, downloads, and names are easy to copy or replace. A Quo
gives creators and readers evidence they can keep with the artifact.

Four terms matter:

- a **persona** is one chosen public role: personal, project, employer-facing,
  or pseudonymous;
- an **artifact** is the exact digital thing being discussed: an article,
  image, archive, software release, plugin, or other file;
- a **proof bundle** is a portable signed statement plus the public material
  needed to check it; and
- **continuity** is signed evidence that one key followed another for the same
  persona.

A Quo does not put every role into one universal identity. A person can keep
separate personas with separate keys. Connecting them is an explicit choice,
not a default database relationship.

## A simple example

Suppose somebody publishes under the fictional persona `JuniperQuill`. They
sign an article and image, rotate their key later, and publish a short-lived
DNS proof for a domain they control.

```text
Persona: JuniperQuill

Evidence available:
- this key signed the exact bytes of this article
- this key signed the exact bytes of this image
- this key follows a verified continuity chain from a separately pinned root
- DNSSEC confirms the domain currently publishes the expected commitment

Not established:
- legal name
- government identity
- whether the article is true
- whether the image is original
- whether the person is trustworthy
```

## Two paths for identity evidence

### 1. A self-created A Quo persona

This path exists in the current prototype. A user can create a personal,
project, organization, employer-facing, or pseudonymous role such as
`JuniperQuill`.

The user enrolls the public key and associates it with an OpenSSH file key,
SSH-agent key, or OpenSSH FIDO security key. A Quo does not import the private
key. FIDO-backed signing still requires the hardware.

The persona can sign prose, images, archives, software releases, Omarchy
plugins, and other files. Verification establishes that the bundled key signed
the exact bytes. With independently obtained root and, for recovery,
latest-policy digests, a verifier can follow supported continuity evidence.

The persona label is self-asserted. A valid proof does not automatically reveal
or establish the user's legal name, age, nationality, address, government
identity, current authorization, or the truth and safety of the artifact.

### 2. Evidence from an external credential wallet

This path is **planned, not implemented**. A **credential wallet** is an
official or authorized application that holds credentials and their private
keys. Swiss swiyu and the EU Digital Identity Wallet are intended integration
targets.

A **claim** is one requested fact. A **presentation** is the wallet's signed
response containing approved evidence. The intended flow is:

1. A Quo or another application requests a specific claim.
2. The authorized wallet shows the request and asks the user to approve it.
3. The wallet returns a narrowly scoped signed presentation.
4. A Quo verifies it and reports exactly what it establishes.
5. The wallet retains the credential and its private keys.

For example:

```text
Requested claim: age requirement of 18 or older
Planned wallet result: requirement satisfied

Not necessarily disclosed:
- exact date of birth
- legal name
- unrelated credentials
```

Selective disclosure is possible only when the credential system supports it.
Other presentations could state Swiss residence, the issuing organization, or
a professional role.

A Quo would not import, own, replace, or store the government wallet, or
override an issuer's revocation. It would report issuer, validity, revocation
evidence, policy, and disclosed facts separately—not mint a universal
“verified person” badge.

## Status at a glance

### Available in the current prototype

These capabilities work in bounded prototype form. “Prototype” does not mean
production-ready, audited, packaged, or sufficient for a high-risk decision.

- **Portable artifact signing and verification:** create, inspect, and verify
  SSHSIG proof bundles offline. The direct signing command lacks trusted
  consent.
- **Personas and key lifecycle:** keep separate personas, bind supported
  signers, rotate or mark keys compromised, and inspect local history. A
  managed current head cannot be compromised outside its journal; a signed
  threshold transition can atomically replace it and record compromise inside
  that journal. SQLite is context, not an independently witnessed ledger.
- **Persona backup:** existing bounded, metadata-only v1 and evidence-only v2
  files remain inspectable and importable. Export now emits v3, whose
  evidence-archive form
  can preserve and internally reverify a supplied signed root, recovery-policy
  chain, mixed routine/recovery history, and an optional final terminal
  revocation, then re-export it. Import initially leaves V2/v3
  evidence quarantined: it installs no signer locator, private or
  recovery secret, live continuity journal, or operational signing or recovery
  authority. No head or revision is serialized; the derived chain tip and
  copied digests are not independent freshness pins. The local prototype can
  now compare one archive per invocation with separately supplied root,
  effective-head, and explicit latest-policy expectations. It reports an exact
  match, an extension beyond the pin, divergence at or before the pin, or a
  shorter/inconclusive candidate. Comparison never selects a branch, proves
  signer custody, or grants authority. An explicit direct-activation store
  prototype can then materialize one exactly pinned, nonterminal archive after
  the caller also pins its archive digest and derived current key and that key
  answers a fresh local custody challenge. The immutable source archive is
  retained beside a sealed materialization receipt; only that validated state
  becomes operational. Exact receipt replay changes no state and performs no
  signer I/O. A recovery-activation prototype handles an unavailable archived
  tip without ever granting that tip local authority. It requires exact
  archive, root, source-head, and latest-policy pins, exactly one
  threshold-authorized recovery proof extending that source head, and fresh
  successor-key custody. One transaction materializes the archived prefix,
  applies the exact recovery transition, and binds only the successor; exact
  replay changes no state and performs no signer I/O. A separate
  terminal-hydration prototype accepts only an exact
  archive digest plus independently supplied root, final terminal-head, and
  latest-policy pins. It projects the verified nonterminal prefix and final
  terminal overlay in one transaction, retains the source archive, and seals a
  receipt recording zero active keys, signer references, custody, signing
  authority, recovery exercise, or reactivation path. Exact replay is
  read-only; the result remains inspectable and `TerminallyRevoked`.
- **Portable continuity:** create a self-signed persona root, rotate between
  two keys that sign the same statement, and verify the ordered history against
  an independently obtained root digest. An optional independently obtained
  head checkpoint detects an older prefix or different signed branch relative
  to that checkpoint. On Linux, the trusted
  `root-request`/`transition-request` prototype adds consent, an append-only
  journal, atomic key handoff, and exact retry recovery for newly journaled
  histories. Routine rotation can continue after a recovery transition has
  been explicitly committed to that live journal. A separately authorized
  terminal leaf can instead end the persona permanently with no successor key.
- **Persona-root distribution:** verify a signed persona root and export its
  public facts as deterministic JSON, accessible text, or a standalone
  printable HTML card with a digest-only QR code. A verifier can keep a
  separate unsigned pin record, label it as first-use, same-channel, or
  user-confirmed out-of-band evidence, and compare it later without silently
  replacing the pin. A Quo reports those routes separately; it cannot prove
  that two channels were truly independent.
- **Threshold recovery protocol:** create versioned policies with distinct
  recovery-only keys, authorize policy changes, create threshold recovery
  transitions, and verify mixed rotation/recovery chains. For an existing live
  persona, record an independently pinned policy chain and atomically commit an
  already-signed recovery or compromise transition, preserving the policy,
  proof, lifecycle audit, successor binding, and historical evidence. Exact
  retries return the first committed proof wrapper. Before a first commit
  changes authority, the configured successor signer must sign a fresh local
  challenge that verifies against the recovery-approved public key; an agent or
  hardware signer must therefore be available then. Exact replay does not
  access the signer. Recovery signing remains a low-level, sequential CLI
  workflow—not a trusted multi-party ceremony. Recovery-policy statement v1
  remains successor-only. Statement v2 grants terminal authority only through
  an explicit signed capability; it can then authorize a final threshold-signed
  no-successor revocation. A first terminal commit atomically deauthorizes the
  current key and removes its signer binding; exact retries return the first
  committed wrapper without restoring authority.
- **Private Linux signing and consent:** a per-user daemon handles immutable
  snapshots over a closed Unix protocol and uses a separate direct-Wayland
  approval process. Its trusted helper must be installed at a fixed root-owned
  path; a source checkout alone fails closed.
- **DNS domain-control evidence:** create short-lived statements, print the TXT
  commitment, verify offline, and optionally check live DNS with DNSSEC. This
  establishes at most current technical publication control of the exact name.
- **Omarchy package handling:** inspect hostile `.tar.zst` plugin releases,
  install a recognized publisher's release atomically in a disabled state, and
  update only to a newer version from the same local publisher persona with
  rollback on shell-rescan failure.
- **Offline C2PA verification on Linux:** validate local embedded content
  binding in an isolated no-network worker—not certificate trust, creator
  identity, CAWG, signing, remote manifests, or sidecars.
- **Offline Sigstore and provenance verification on Linux:** verify a v0.3
  bundle under an explicit root and certificate policy, then report
  authenticated in-toto/SLSA claims without assigning a Build level.

### Still requires hardening, product, and release work

- independent security review and broader hostile-input, coverage-guided fuzz,
  race, migration, and platform fault testing;
- packaged lifecycle testing and polished recovery/migration UX for trusted
  routine rotation and journaled recovery, trusted multi-party recovery
  consent, terminal-revocation ceremony and distribution, direct archive
  activation, recovery archive activation, and terminal-hydration CLI/product
  hardening, multi-archive comparison and safe fork handling, and independently
  witnessed root and policy freshness;
- an accessible, compositor-protected approval path tested with real assistive
  technology, without giving another process approval authority;
- installable Omarchy/Linux packaging, clean-system lifecycle tests, and tests
  with real plugins;
- packaged and assistive-technology-tested root distribution, plus polished
  recovery, migration, and restoration experiences;
- A Quo release provenance, project build policies, reproducible-build
  comparison, and TUF freshness/rollback metadata; and
- C2PA certificate/trust policy and current Sigstore trust-root distribution
  and revocation policy.

### Future integrations

- Swiss swiyu and EU Digital Identity Wallet presentation hand-offs;
- optional DID and blockchain-account adapters without requiring a blockchain
  or equating an account with a legal person;
- native consent, keystore, and parser-isolation adapters for macOS, Windows,
  and Linux distributions beyond the initial Omarchy work; and
- C2PA signing, certificate trust, CAWG identity validation, sidecars, and an
  explicitly reviewed link between media evidence and an A Quo persona.

## What the evidence can—and cannot—say

A Quo treats trust as separate questions. Evidence may establish:

- integrity of the exact artifact bytes;
- control of the signing key for that statement;
- continuity from a root digest obtained through a separate trusted channel;
- recognition of the signing key as part of a local publisher persona;
- a specific verified claim from an external wallet, once that integration
  exists; or
- current technical DNS publication control for one exact name.

None of those automatically establishes:

- legal or government identity;
- truth, originality, authorship, or copyright ownership;
- absence of malware, dangerous permissions, or unwanted behavior;
- source review, reproducible building, quality, or general safety;
- current authorization, non-revocation, or freshness beyond the evidence
  actually checked; or
- that a person, organization, key, credential issuer, or build system is
  generally trustworthy.

Reports preserve these distinctions instead of showing one green “safe” or
“verified identity” badge. In technical shorthand, **trust is a vector**:
independent answers, not one score.

## How verification works

For an ordinary file, A Quo:

1. digests the exact bytes and creates a purpose-specific persona statement;
2. has the selected key sign it and packages the public verification material;
3. lets a verifier recalculate the digest, check the signature, and report the
   evidence and important unknowns.

The stronger Linux path keeps key control away from the caller. A local service
snapshots the open artifact, shows it for approval, and verifies the proof
before release.

Continuity proofs add a persona-specific root and signed transitions. Domain,
C2PA, Sigstore, and future wallet presentations remain separate evidence
adapters because they answer different questions and have different trust
sources.

## Omarchy: the first concrete integration

Omarchy plugins run code in a user's desktop session, so publisher evidence is
useful—but it is not a sandbox or malware verdict. A Quo's current adapter
works with an immutable local release archive rather than downloading a moving
branch.

Before installation, it verifies the exact package, checks for an active local
publisher persona, parses without executing, lists executable files, and keeps
runtime safety unevaluated. Private staging leaves a new plugin disabled.
Updates require the same persona and a strictly newer version; a failed shell
rescan triggers an atomic rollback attempt.

```text
A Quo can establish:
- these are the exact signed package bytes
- this key belongs to the locally recognized publisher persona
- this update comes from that same persona
- this update is not an equal-version replacement or downgrade

A Quo cannot establish:
- that the plugin is harmless
- that its source was reviewed
- that it should receive unrestricted access
```

## Other evidence examples

| Evidence | Current result | Important limit |
| --- | --- | --- |
| Signed prose, images, archives, or releases | Verifies exact bytes and signing key | Does not establish truth, originality, or safety |
| Persona continuity | Verifies signed key transitions from a separately pinned root; an optional pinned head rejects older prefixes and other branches relative to that pin. A quarantined archive can be compared with exact root/head/policy expectations without activating it. Direct activation additionally requires an exact archive digest, current-key pin, and live custody proof before creating local authority. Recovery activation instead requires an active pinned recovery policy, exactly one authorized transition extending the pinned source head, and fresh successor custody; it never activates the archived tip. Terminal hydration requires the exact final terminal head and policy and creates frozen, inspectable zero-authority state | Does not establish legal identity, checkpoint independence or freshness, absence of a hidden sibling or newer history, or future signer availability |
| DNS domain proof | Can verify a fresh exact-name TXT commitment and DNSSEC state | Does not establish legal ownership or control of every website at that name |
| Embedded C2PA media | Validates local content binding in the Linux prototype | Does not yet trust the certificate, creator identity, or CAWG assertion |
| Sigstore/in-toto/SLSA | Verifies bundle cryptography and authenticated claims under explicit policy | Does not establish acceptable build policy, reproducibility, or artifact safety |
| External credential presentation | Planned verification of a narrowly requested claim | Wallet custody, issuer policy, selective disclosure, validity, and revocation remain separate |

## Prototype usage

Install [Mise](https://mise.jdx.dev/), trust the repository configuration, and
use the pinned toolchain. The examples below run from a source checkout.

Create a persona, enroll its public key, and bind a supported local signer:

```sh
mise exec -- cargo run -p a-quo-cli -- persona create \
  --label "Example Publisher" --purpose project

mise exec -- cargo run -p a-quo-cli -- persona key-add \
  --persona-id PERSONA_ID \
  --public-key ~/.ssh/id_ed25519.pub \
  --provider openssh-file

mise exec -- cargo run -p a-quo-cli -- persona key-bind \
  --fingerprint KEY_FINGERPRINT \
  --signing-key ~/.ssh/id_ed25519
```

`key-bind` stores only the resolved local path, not private-key bytes. For an
SSH-agent persona, bind the matching public-key stub. For a FIDO persona, bind
the OpenSSH security-key stub.

The low-level direct command is useful for development and explicit scripts,
but it bypasses A Quo's trusted consent screen:

```sh
mise exec -- cargo run -p a-quo-cli -- sign article.md \
  --key ~/.ssh/id_ed25519 \
  --public-key ~/.ssh/id_ed25519.pub \
  --persona-id PERSONA_ID

mise exec -- cargo run -p a-quo-cli -- verify article.md \
  --proof article.md.a-quo-proof.json
```

With `--persona-id`, A Quo revalidates the registered key and persona inside a
database authorization guard held through signing and proof publication. An
archived, quarantined, inactive, or terminally revoked persona cannot use this
path. The separate raw `--persona LABEL` form makes only an unregistered label
claim. Neither direct form provides trusted user consent.

With the packaged Linux daemon and trusted helper installed, request an
interactive exact-artifact signature without passing a signer path to the
client:

```sh
mise exec -- cargo run -p a-quo-cli -- request-sign article.md \
  --persona-id PERSONA_ID --kind article
```

Create a consented persona root on Linux, obtain its printed digest through a
separate trusted channel, and ask the current and proposed keys to sign one
approved routine rotation:

```sh
mise exec -- cargo run -p a-quo-cli -- continuity root-request \
  --persona-id PERSONA_ID \
  --output publisher.a-quo-persona-root.json

mise exec -- cargo run -p a-quo-cli -- continuity root-card-export \
  --root publisher.a-quo-persona-root.json \
  --format json \
  --output publisher.a-quo-persona-root-card.json

mise exec -- cargo run -p a-quo-cli -- continuity root-card-export \
  --root publisher.a-quo-persona-root.json \
  --format html \
  --output publisher.a-quo-persona-root-card.html

mise exec -- cargo run -p a-quo-cli -- continuity root-pin-create \
  --pin-uri 'aquo:persona-root-pin:v1:FULL_64_CHARACTER_DIGEST' \
  --basis out-of-band-user-confirmed \
  --channel paper \
  --output verifier.a-quo-persona-root-pin.json

mise exec -- cargo run -p a-quo-cli -- continuity root-pin-compare \
  --root publisher.a-quo-persona-root.json \
  --card publisher.a-quo-persona-root-card.json \
  --pin verifier.a-quo-persona-root-pin.json

mise exec -- cargo run -p a-quo-cli -- continuity transition-request \
  --persona-id PERSONA_ID \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --next-key ~/.ssh/id_ed25519_next \
  --next-public-key ~/.ssh/id_ed25519_next.pub \
  --next-provider openssh-file \
  --output publisher.rotation-1.json

mise exec -- cargo run -p a-quo-cli -- continuity chain-verify \
  --root publisher.a-quo-persona-root.json \
  --transition publisher.rotation-1.json \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --expected-head-sequence 1 \
  --expected-head-sha256 INDEPENDENT_ROTATION_STATEMENT_DIGEST
```

The daemon commits before returning. Exact retries recover the same proof;
other outputs are not overwritten. Root-card and pin outputs are public or
verifier-owned evidence, never secret or signing authority, and existing files
are not overwritten. For first-use or same-channel pinning, run
`root-pin-create --from-root` without an acceptance digest first: it prints the
verified root facts and writes nothing. Only a second run with the exact
`--accept-root-sha256` shown in that review can create the pin. The digest-only
URI must come through the route the user labels as separate; the card itself
cannot supply independent evidence. The store can compare—but cannot
independently source—the root pin. Roots that exist only as files and
quarantined backup archives are never silently adopted into the live journal;
the separate activation and hydration commands below require exact external
expectations. Recovery
proof signing remains a low-level workflow, but routine `transition-request`
can continue after an explicitly committed recovery; see
[Portable persona continuity](docs/CONTINUITY.md).
Omit the expected-head pair when only a root pin is available; A Quo then calls
the result the key at the supplied chain tip and explicitly says that newer or
competing history may have been withheld.

Compare one quarantined backup archive with checkpoints obtained separately
from that archive:

```sh
mise exec -- cargo run -p a-quo-cli -- persona backup-compare \
  publisher.a-quo-persona-backup.json \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --expected-head-sequence 2 \
  --expected-head-sha256 INDEPENDENT_EFFECTIVE_HEAD_DIGEST \
  --expected-policy-version 1 \
  --expected-policy-sha256 INDEPENDENT_LATEST_POLICY_DIGEST \
  --json
```

Use `--expect-no-recovery-policy` instead of the two policy options only when
the independently expected state is no policy. For terminal v3 archives, the
effective head is the final terminal leaf. A shorter archive is reported as
`shorter_than_expected_inconclusive`, not as a proven prefix: a later digest
cannot show whether the unseen earlier entry would have matched.

This comparison is non-mutating and always leaves
`current_signer_custody=false`, `signing_authority=false`, and the archive
evidence-only/quarantined. It works for one archive per invocation; it neither
chooses among candidates nor proves that the supplied checkpoints are
independent or fresh. Its current maturity and remaining gates are tracked by
[#27](https://github.com/SurreptitiousFabric/a-quo/issues/27) and the
[maturity audit](docs/MATURITY-AUDIT.md).

Direct archive activation is implemented in the current bounded CLI/store
prototype under [#29](https://github.com/SurreptitiousFabric/a-quo/issues/29).
It is a
separate, explicit state change—a successful `backup-compare` report never
activates anything. The first activation requires exact expectations for the
stored archive digest, root, effective head, latest-policy state, and derived
current-key fingerprint. The user chooses the local signer provider and
canonical locator; A Quo proves live custody of that exact key, reverifies the
source inside one immediate write transaction, projects the signed history,
and seals an immutable receipt. Failure at any stage leaves the original
evidence-only archive unchanged.

After importing that exact archive into the target store, activate it with the
independently retained values—not values accepted merely because the same
archive repeats them:

```sh
mise exec -- cargo run -p a-quo-cli -- persona backup-activate-direct \
  --persona-id PERSONA_ID \
  --expected-archive-sha256 EXACT_ARCHIVE_DIGEST \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --expected-head-sequence 2 \
  --expected-head-sha256 INDEPENDENT_EFFECTIVE_HEAD_DIGEST \
  --expected-policy-version 1 \
  --expected-policy-sha256 INDEPENDENT_LATEST_POLICY_DIGEST \
  --expected-current-key-fingerprint INDEPENDENT_CURRENT_KEY_FINGERPRINT \
  --current-provider openssh-file \
  --current-signing-locator /absolute/path/to/current-key \
  --json
```

Use `--expect-no-recovery-policy` instead of the policy-version/digest pair
only when that is the independently expected state. Both signer options are
required for first activation and may both be omitted for an exact sealed
replay. The command accepts no archive path, `--latest`, or `--force`: it acts
only on the quarantined archive already stored under `--persona-id`.

The typed source archive remains byte-for-byte unchanged in the store. Its
unsigned persona purpose, lifecycle timestamps, event actors, policies, and
notes are retained as imported context, not promoted into signed facts. The
receipt records the exact source, pins, source/result heads, current key,
signer binding, local materialization time, and pre-existing audit boundaries.
The initial binding and every later rebind commit to a non-secret digest of
the canonical local locator. Authority reads replay that event suffix and fail
if its times, state changes, or current binding row no longer agree.
An exact retry returns that first receipt without opening or challenging the
signer; a changed archive, pin, key, provider, or locator conflicts before
signer I/O. Historical custody at materialization is not a claim that the
signer is still available now. This remains a low-level prototype operation,
not the packaged trusted-consent and recovery experience.

Activation accepts future unsigned export and archive-observation times as
untrusted context, but rejects signed issuance times or imported lifecycle
claims later than the local activation time. This local clock rule prevents
future-dated imported authority from entering the live journal; it is not a
trusted timestamp and does not establish archive freshness. An expired
recovery policy is reported but does not block direct activation because this
mode exercises no recovery authority.

Recovery archive activation is the separate authority-bearing operation
implemented as a bounded CLI/store prototype under
[#30](https://github.com/SurreptitiousFabric/a-quo/issues/30). It is for an
already-imported nonterminal archive whose archived tip is unavailable. The
request pins the exact archive, root, source head, and active latest policy and
supplies exactly one threshold-authorized recovery proof that extends that
source head. The archived tip never becomes local authority. The first request
also chooses the successor provider and locator and proves fresh custody of the
recovery-approved successor:

```sh
mise exec -- cargo run -p a-quo-cli -- persona backup-activate-recovery \
  --persona-id PERSONA_ID \
  --proof publisher.recovery.json \
  --expected-archive-sha256 EXACT_ARCHIVE_DIGEST \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --expected-head-sequence 2 \
  --expected-head-sha256 INDEPENDENT_SOURCE_HEAD_DIGEST \
  --expected-policy-version 1 \
  --expected-policy-sha256 INDEPENDENT_LATEST_POLICY_DIGEST \
  --next-provider openssh-file \
  --next-signing-locator /absolute/path/to/successor-key \
  --json
```

The head expectation names the archived source head; the recovery proof supplies
the result head and successor. Both successor signer options are required on
first activation and may both be omitted for an exact sealed replay. One
immediate transaction materializes the archived prefix, deauthorizes its tip
under the signed recovery reason, appends the exact recovery proof, binds the
successor, and seals distinct source and result heads. A changed proof, pin,
provider, or locator conflicts with the receipt. Exact replay changes no state
and performs no signer I/O even if the successor path is no longer available.
This remains a low-level sequential recovery workflow, not trusted multi-party
consent. It does not prove that the pins were independent or fresh, exclude a
withheld sibling or newer branch, establish legal identity, or make signed
material safe.

Terminal archive hydration is the separate zero-authority operation implemented
under [#28](https://github.com/SurreptitiousFabric/a-quo/issues/28). It accepts
only a terminal v3 archive already imported under the named persona and exact
expectations for the archive, root, final terminal leaf, and latest policy. It
does not accept a signer, provider, locator, current-key pin, recovery proof,
`--latest`, or `--force`:

```sh
mise exec -- cargo run -p a-quo-cli -- persona backup-hydrate-terminal \
  --persona-id PERSONA_ID \
  --expected-archive-sha256 EXACT_ARCHIVE_DIGEST \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --expected-head-sequence 3 \
  --expected-head-sha256 INDEPENDENT_FINAL_TERMINAL_DIGEST \
  --expected-policy-version 1 \
  --expected-policy-sha256 INDEPENDENT_LATEST_POLICY_DIGEST \
  --json
```

A Quo fully reverifies the unique final terminal proof, then uses one immediate
transaction to project the signed root, policies, nonterminal prefix, and
terminal overlay and seal the exact receipt. The SQL continuity head remains
the preterminal key head; reports separately name the final terminal leaf as
the effective head. The retained archive remains available for historical
verification, but the materialized persona has no active key, signer reference,
custody claim, signing or recovery authority, or reactivation route. An expired
latest policy is reported and accepted because hydration exercises no recovery
authority. Exact retry is read-only. These properties do not prove that the
external pins were independent or fresh, that no sibling was withheld, or that
historically signed material is safe or true.

All three explicit one-archive materialization modes now have bounded prototypes
under [#26](https://github.com/SurreptitiousFabric/a-quo/issues/26): direct
activation ([#29](https://github.com/SurreptitiousFabric/a-quo/issues/29)),
terminal hydration ([#28](https://github.com/SurreptitiousFabric/a-quo/issues/28)),
and recovery activation
([#30](https://github.com/SurreptitiousFabric/a-quo/issues/30)). Remaining #26
work includes multi-candidate UX, existing-live fork handling, product and
contention hardening, trusted consent, and independent review. No mode selects
among multiple candidates, resolves an existing live fork, establishes that
pins were independently or freshly obtained, proves legal identity, or proves
artifact safety.

The live-store recovery commands are discoverable directly from the compiled
CLI:

```sh
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-policy-record --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-transition-commit --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity terminal-revocation-create --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity terminal-revocation-verify --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity terminal-revocation-commit --help
mise exec -- cargo run -p a-quo-cli -- \
  persona backup-activate-recovery --help
mise exec -- cargo run -p a-quo-cli -- \
  persona backup-hydrate-terminal --help
```

`recovery-policy-record` and `recovery-transition-commit` both require
independently obtained root and latest-policy pins. Policy recording also pins
the current transition head. Recovery commit instead pins
the exact previous head named by the transition: a first commit requires that
checkpoint to be the live head, while an exact replay additionally requires
the already committed recovery statement to remain the fully verified current
head. A first recovery commit also requires the next provider and signer
locator; an exact current-head replay can omit both and reuse the verified
stored binding. Terminal policy authority must be selected explicitly; a
terminal commit accepts no successor provider or locator, permanently removes
local authority for that persona root, and preserves the exact signed leaf for
verification and backup. Historical signatures remain inspectable. Without a
separately held terminal head checkpoint, a verifier still cannot exclude a
coherent older database copy or withheld sibling branch. See
[Persona continuity, backup, and recovery](docs/KEY-RECOVERY.md) for the
complete workflow, zero-head rule, atomic commit behavior, and non-claims.

Create and verify short-lived domain evidence:

```sh
mise exec -- cargo run -p a-quo-cli -- domain request-proof YOUR_DOMAIN \
  --persona-id PERSONA_ID

mise exec -- cargo run -p a-quo-cli -- domain verify \
  --proof YOUR_DOMAIN.a-quo-domain-proof.json

mise exec -- cargo run -p a-quo-cli -- domain verify \
  --proof YOUR_DOMAIN.a-quo-domain-proof.json --live
```

Inspect and explicitly install or update a signed Omarchy release:

```sh
mise exec -- cargo run -p a-quo-cli -- omarchy inspect plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json

mise exec -- cargo run -p a-quo-cli -- omarchy install plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json --yes

mise exec -- cargo run -p a-quo-cli -- omarchy update plugin-v2.tar.zst \
  --proof plugin-v2.tar.zst.a-quo-proof.json --yes
```

`--yes` confirms review of that exact package; it is not a safety override.

Verify local embedded C2PA evidence or an offline Sigstore bundle:

```sh
mise exec -- cargo run -p a-quo-cli -- media verify photo.jpg

mise exec -- cargo run -p a-quo-cli -- supply-chain verify-bundle plugin.tar.zst \
  --bundle plugin.tar.zst.sigstore.json \
  --trusted-root trusted_root.json \
  --identity 'EXPECTED CERTIFICATE IDENTITY' \
  --issuer 'EXPECTED OIDC ISSUER'
```

## Security architecture in brief

- **Keys stay with their provider.** A Quo stores public material, persona
  policy, lifecycle records, and an explicitly configured signer path—not
  private-key contents or official-wallet credentials.
- **Consent is outside the caller.** On Linux, signing authority lives behind a
  private, versioned Unix-socket protocol—not D-Bus or an Omarchy bar process.
  The separate Wayland consent process receives display evidence, not artifact
  bytes, signer paths, or keys.
- **The approved bytes are fixed.** File-descriptor passing, bounded immutable
  snapshots, separated purposes, and post-sign verification resist mutable-file
  substitution. Rotation displays both keys and the exact statement digest.
- **Verification work is bounded.** Live persona journals enforce count and
  aggregate-byte limits before one native cryptographic pass, including space
  for a proposed append before it can mutate the journal. OpenSSH remains the
  signing boundary for file, agent, and hardware-backed keys.
- **Hostile parsers are isolated.** Archive inputs are bounded and inspected
  without execution. C2PA and Sigstore inputs run in separate no-network Linux
  workers rather than in the signing daemon.
- **Personas remain separate.** Random local identifiers and persona-specific
  roots are not derived from a universal identity. Reusing a label or key can
  still correlate activity, so privacy also depends on user choices.
- **Reports preserve uncertainty.** Integrity, key identity, continuity,
  issuer evidence, freshness, revocation, build provenance, review, and safety
  remain separate fields.

Same-user malware can still modify local files and desktop state. The
prototype has no external security audit, trusted timestamp service, general
revocation service, or complete accessibility path. See the threat model for
the full boundary and residual risks.

## Technical documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Proof format](docs/PROOF-FORMAT.md)
- [Personas and key history](docs/PERSONAS.md)
- [Persona continuity, backup, and recovery](docs/KEY-RECOVERY.md)
- [Portable persona continuity format](docs/CONTINUITY.md)
- [Persona-root distribution and pinning](docs/ROOT-DISTRIBUTION.md)
- [Private signing daemon](docs/DAEMON.md)
- [Consent IPC](docs/CONSENT-IPC.md)
- [Signed Omarchy packages](docs/OMARCHY.md)
- [DNS domain-control proofs](docs/DOMAIN-CONTROL.md)
- [Offline C2PA verification](docs/C2PA.md)
- [Offline Sigstore and SLSA verification](docs/SUPPLY-CHAIN.md)
- [Maturity definitions](docs/MATURITY.md)
- [A Quo 0.x maturity audit](docs/MATURITY-AUDIT.md)
- [Roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md)
- [Witness Me! public Project](https://github.com/users/SurreptitiousFabric/projects/9)

## Development

Install [Mise](https://mise.jdx.dev/), then run:

```sh
mise trust
mise install
mise run check
mise run audit
```

No system Rust installation is expected or supported by this repository.

## Status and license

Do not use this prototype as the sole authorization control for a high-risk
installation or as a replacement for an official Swiss or EU credential
wallet. Work is tracked on the
[Witness Me! Project](https://github.com/users/SurreptitiousFabric/projects/9).

Apache-2.0. See [`LICENSE`](LICENSE).
