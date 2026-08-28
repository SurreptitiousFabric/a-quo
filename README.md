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

Suppose somebody publishes as `Aelectricmonk`. They create a matching persona,
sign an article and image, rotate their key later, and publish a short-lived
DNS proof for `aelectricmonk.ch`.

```text
Persona: Aelectricmonk

Evidence available:
- this key signed the exact bytes of this article
- this key signed the exact bytes of this image
- this key follows a verified continuity chain from a separately pinned root
- DNSSEC confirms aelectricmonk.ch currently publishes the expected commitment

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
`Aelectricmonk`.

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

- **Portable artifact signing and verification:** create SSHSIG proof bundles
  for exact files, inspect their claims, and verify them offline. The low-level
  signing command invokes OpenSSH directly and does not provide the stronger
  trusted-consent flow.
- **Personas and key lifecycle:** keep separate local personas, enroll public
  keys, bind supported signers, rotate keys, record compromise events, and
  inspect history. The local SQLite history is useful context, not an
  independently witnessed ledger.
- **Persona backup:** export, inspect, and restore bounded non-secret metadata.
  Backups exclude private keys, signer paths, recovery secrets, and wallet
  credentials; they are not recovery authority.
- **Portable continuity:** create a self-signed persona root and dual-signed
  routine key transitions, then verify an ordered chain against an
  independently obtained root digest. Trusted two-key transition consent is
  still pending.
- **Threshold recovery protocol:** create versioned policies with distinct
  recovery-only keys, authorize policy changes, create threshold recovery
  transitions, and verify mixed rotation/recovery chains. This is a low-level,
  sequential CLI prototype—not yet a trusted multi-party ceremony.
- **Private Linux signing and consent:** a per-user daemon receives immutable
  snapshots through a closed Unix protocol, invokes a separate direct-Wayland
  approval process, verifies the result, and returns a sealed proof. Its
  trusted helper needs the fixed root-owned installation path; a source
  checkout alone fails closed.
- **DNS domain-control evidence:** create short-lived statements, print the TXT
  commitment, verify offline, and optionally check live DNS with DNSSEC. This
  establishes at most current technical publication control of the exact name.
- **Omarchy package handling:** inspect hostile `.tar.zst` plugin releases,
  install a recognized publisher's release atomically in a disabled state, and
  update only to a newer version from the same local publisher persona with
  rollback on shell-rescan failure.
- **Offline C2PA verification on Linux:** validate an embedded local media
  content binding in an isolated no-network worker. Certificate trust, creator
  identity, CAWG validation, signing, remote manifests, and sidecars are not
  established.
- **Offline Sigstore and provenance verification on Linux:** verify a Sigstore
  v0.3 bundle against a supplied trusted-root snapshot and exact certificate
  policy, then report authenticated in-toto/SLSA claims. A Quo assigns no SLSA
  Build level and does not approve the claimed build settings.

### Still requires hardening, product, and release work

- independent security review and broader hostile-input, fuzz, property, race,
  interruption, migration, and rollback testing;
- trusted two-key rotation and trusted multi-party recovery consent, plus
  independently witnessed root and policy freshness;
- an accessible trusted approval path tested with real assistive technology,
  without giving another process approval authority;
- installable Omarchy/Linux packaging, clean-system lifecycle tests, and tests
  with real plugins;
- clearer root distribution, recovery, migration, and restoration experiences;
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

For an ordinary file, the high-level flow is:

1. A Quo calculates a cryptographic digest of the exact artifact bytes.
2. It creates a statement describing those bytes and the selected persona.
3. The selected key signs that statement in an artifact-specific context, so
   the proof cannot be silently reused as a domain or recovery authorization.
   The current article/image label is consent-screen context, not a signed v1
   claim.
4. A Quo stores the statement, signature, and public verification material in
   a proof bundle.
5. A verifier recalculates the artifact digest, checks the signature, and
   reports every available evidence dimension and every important unknown.

The stronger Linux path keeps direct signing-key control away from the calling
application. A local service snapshots an already-open artifact, shows what is
being signed, and verifies the proof before releasing it.

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
| Persona continuity | Verifies signed key transitions from a separately pinned root | Does not establish legal identity or that the latest history was not withheld |
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

With the packaged Linux daemon and trusted helper installed, request an
interactive exact-artifact signature without passing a signer path to the
client:

```sh
mise exec -- cargo run -p a-quo-cli -- request-sign article.md \
  --persona-id PERSONA_ID --kind article
```

Create a consented persona root on Linux and verify a continuity chain against
a root digest obtained somewhere else:

```sh
mise exec -- cargo run -p a-quo-cli -- continuity root-request \
  --persona-id PERSONA_ID \
  --output publisher.a-quo-persona-root.json

mise exec -- cargo run -p a-quo-cli -- continuity chain-verify \
  --root publisher.a-quo-persona-root.json \
  --transition TRANSITION_PROOF \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST
```

The complete routine-rotation and threshold-recovery commands are documented
in [Portable persona continuity](docs/CONTINUITY.md). Do not automate the
low-level multi-key commands as though they were a reviewed recovery ceremony.

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
  snapshots, purpose-separated statements, and post-sign verification reduce
  path substitution and mutable-file attacks.
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
