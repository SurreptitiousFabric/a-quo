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
  access the signer. A bounded Linux prototype can now coordinate one recovery
  transition as portable `start`, independently consented `respond`, and
  deterministic `assemble` steps. Every participant supplies their own root,
  latest-policy, and previous-head pins; A Quo derives their role from their
  key and, through the private Unix socket and direct-Wayland prompt, creates
  purpose-separated signatures over the exact request and short-lived
  transition statement. The portable request and responses contain no local
  persona UUID or private signer locator. Assembly changes no persona state:
  the resulting ordinary recovery proof must still be committed or used for
  recovery archive activation separately and before its signed expiry on first
  use. Policy creation/update, the direct `recovery-transition-create`
  command, and terminal revocation remain low-level sequential workflows.
  Recovery-policy statement v1 remains successor-only. Statement v2 grants
  terminal authority only through an explicit signed capability; it can then
  authorize a final threshold-signed no-successor revocation. A first terminal
  commit atomically deauthorizes the current key and removes its signer binding;
  exact retries return the first committed wrapper without restoring authority.
- **Private Linux signing and consent:** a per-user daemon handles immutable
  snapshots over a closed Unix protocol and uses a separate direct-Wayland
  approval process. Its trusted helper must be installed at a fixed root-owned
  path; a source checkout alone fails closed.
- **DNS domain-control evidence:** create short-lived statements, print the TXT
  commitment, verify offline, and optionally check live DNS with DNSSEC. This
  establishes at most current technical publication control of the exact name.
- **Omarchy package handling:** inspect hostile `.tar.zst` plugin releases,
  give a recognized publisher's release an atomic no-replace namespace move
  without an A Quo enable action, and update only to a newer version from the
  same local publisher persona. A read-only reference observer reports whether
  the exact plugin ID appears in the accepted persisted Omarchy configuration,
  whether those raw
  bytes came from the user or packaged default, and their SHA-256. It does not
  return the configuration contents or claim that the running shell applied
  them, enabled the plugin, or loaded it. Bounded Linux fresh install and update
  both make one kernel-sealed snapshot after a no-follow, nonblocking,
  size-bounded source copy, then use those same bytes for proof verification,
  archive inspection, extraction, and the receipt's package digest. Fresh
  install binds the extracted candidate and
  local receipt to a bounded tree snapshot, pins its directory and both parent
  directories, runs Omarchy's validator from the pinned root, uses pinned-parent
  no-replace exposure, and accepts success only after the live inode and tree
  revalidate after rescan. If that exposure passed its postcheck but the first
  rescan or late publisher-authorization finalization fails, fresh install
  attempts to move only the still-exact candidate back to an empty retained
  staging slot, requests a restoration rescan, and verifies the restored layout
  and a fresh unreferenced configuration observation. Automatic staging cleanup
  is disabled from creation; success and many failures report retained private
  staging, and no automatic purge runs. Update additionally pins the installed
  tree, exchanges releases descriptor-relatively, retains the prior release,
  and attempts guarded rollback with post-verification on bounded late
  failures. These are
  point-in-time integrity guarantees, not
  permanent immutability. Every lifecycle `renameat2` call pins its parent
  directories but still resolves child names in the syscall. A same-user swap
  after the last userspace check can therefore cause a wrong or transient move;
  postchecks reject false success. Guarded rollback requires the exact live tree
  before its syscall and reports detected mismatches, but its own postcheck can
  still discover that the child-name race moved a wrong tree. An exposure
  postcheck failure, or a final layout failure after a successful initial
  rescan, is not automatically rolled back. Standalone
  inspection still reopens its caller's path. Crash
  durability, safe purge, inode-conditional moves, and race-free unreferenced
  exposure remain release gates; the last requires Omarchy cooperation through
  a coordinated transaction or inhibit interface.
- **Guarded joined Omarchy v2 package journey (contract only):** the package
  bridge now composes an exact intended real-Pacman old install and new upgrade
  with the installed daemon's operator-observed decline for v1 followed by
  approvals for v1 and v2. The consent evaluator retains a public persona, two
  exact proofs, and their strict handoff manifest after unbinding the signer and
  removing the original disposable key paths; same-UID copying or access while
  the key existed is not excluded. The installed-core evaluator consumes that
  handoff to verify both exact packages and proofs, install v1, update to v2,
  refuse a v1 downgrade with the same final managed-tree digest, and uninstall
  v2 into retained quarantine. It also requires the recovered v1 and quarantined
  v2 full-tree digests to match their pre-move states. These are final-state
  comparisons; they do not exclude transient mutation or byte-identical
  replacement. The outer bridge cross-checks both packages and proofs, the
  manifest, persona, fingerprint, and retained-store digest before continuing.
  Before its first Pacman mutation, the bridge also verifies both A Quo package
  snapshots against the explicit frozen AArch64 v2 target profile, requires
  their accepted verifier receipts to contain the same exact profile ID,
  profile digest, architecture, target kind, and evidence namespace, and passes
  that tuple through the sanitized consent and core environments. Both nested
  evidence documents and the outer evidence repeat the tuple; the bridge
  rejects a mismatch, duplicate override, cross-profile handoff, or claim that
  x86_64 evidence satisfied the AArch64 gate. This is source-contract
  hardening only and does not authorize the separate x86_64 lane or stage 6.
  This same-UID handoff is not independently authenticated, and the core alone
  does not establish trusted consent. The bridge then removes and
  reinstalls A Quo while requiring retained user evidence to remain byte-for-
  byte unchanged. Separate non-mutating contracts cover the consent handoff,
  the preconsented core branch, and the outer bridge. The acknowledged
  destructive path has **never run**, so this is not real package, runtime, or
  clean-system evidence. Installation consent consists only of the existing CLI
  acknowledgements; secure attention is not established. No behavioural
  provider or scanner runs, and signed does not mean safe. Joined rollback-
  failure and interruption behavior remain future work.
- **Reviewed Ubuntu OCI input selection:** one closed lock now selects the four
  exact ARM64 OCI objects already named by the unarmed Omarchy profile. A
  Linux-only Rust verifier pins a caller-supplied directory and each object
  without following links, copies data once from identity-checked descriptors
  into sealed snapshots, and checks hashes,
  index/manifest/config/layer bindings, and the uncompressed DiffID from those
  same snapshots. The historical acquisition receipt is optional review
  context, not authority. The lock does not publish or durably retain the
  bytes, authorize an image build, make the target runnable, authenticate
  Ubuntu, or establish provenance, freshness, or safety.
- **Candidate-only Ubuntu APT snapshot capture:** a non-root, private-root
  acquisition path uses the retained ARM64 OCI layer to run APT update,
  simulation, and download-only operations for the profile's 14 requests. Its
  offline verifier closes retained byte identities and package/solver transcript
  consistency without installing a package or starting a VM. Two ignored,
  same-host complete runs retained byte-identical sets of 19 indexes and 93
  packages from caller-selected snapshot `20260831T000000Z`. They grant no
  authority or independent reproduction and do not close input class 02:
  the frozen base names the ports archive while the candidate used the main
  timestamped Ubuntu snapshot archive, and archive equivalence, publisher
  authentication, trusted time, freshness, independent closure verification,
  durable retention, safety, build authorization, and the final image remain
  unestablished.
- **Reviewed Omarchy builder-context selection:** a second Linux-only verifier
  binds the ten exact source blobs used by the current Asahi fresh-VM harness
  and checks seventeen dependency references from sealed snapshots of a
  caller-supplied inert export. It invokes neither Git nor the harness and has
  no network or process-execution path. This closes only input class 03's
  exact-byte selection; the frozen profile retains its historical ten-item
  prerequisite record and would still have nine unresolved input classes if
  this lock were adopted. It does not retain source bytes, authorize a build,
  create a runnable image, or establish provenance, freshness, or safety.
- **Omarchy risk-record shape/binding prototype:** parse and canonicalize closed
  publisher, structure, update-delta, local-policy, policy-result, and
  operation-assessment records; check internal structural facts and derivable
  cross-record subject/digest/file-delta/continuity/policy bindings; and check
  one fictional golden update that blocks because scanner evidence cannot yet
  be compared. This is exact-subject, structure, policy, and binding work—not
  behavioural analysis. The candidate surface now treats native scanner
  reports as opaque attachments and contains no parallel capability, evidence,
  observation, or coverage model. The intended integration retains Plug &
  Prejudice's native report and binds it to the exact signed pre-install
  snapshot rather than creating a second behavioural evidence language. This
  is not connected to the current installer and is not a scanner, eligibility
  check, trusted prompt, safety verdict, or frozen v1 protocol.
  A Quo's identity, signature, package-structure, staging, update, and rollback
  functions remain useful without a reviewer adapter, but behavioural analysis
  is then explicitly unavailable and policy must block or request clearly
  warned consent—never report the plugin as clean. Plug & Prejudice is the
  intended first supported optional adapter, not inseparable core; its provisional
  package boundary is `a-quo-provider-plug-and-prejudice`.
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
  routine rotation and journaled recovery; distributed recovery-policy
  enrollment/update and terminal-revocation ceremonies; packaging,
  accessibility, real independent-holder validation, and product hardening for
  the recovery-transition ceremony; direct archive activation, recovery
  archive activation, and terminal-hydration CLI/product hardening;
  multi-archive comparison and safe fork handling; and independently witnessed
  root and policy freshness;
- an accessible, compositor-protected approval path tested with real assistive
  technology, without giving another process approval authority;
- installable Omarchy/Linux packaging, clean-system lifecycle tests, and full
  tests with real plugins; the current fakeroot/libalpm install-remove and
  exact old-to-new/remove/reinstall smokes are only preliminary isolated
  package-transaction checks. A strict six-revision source
  registry and deterministic unsigned raw-Git-object package-builder prototype
  now exist. Exact package/tar digests from two byte-identical same-host cohort
  builds are frozen, while package publication, proofs,
  independent-environment reproduction, hostile variants, and clean-system
  evidence do not exist;
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
works with a fixed local release archive rather than downloading a moving
branch. Bounded Linux fresh install and update make their own kernel-sealed
package snapshots; the standalone inspector does not yet share that hardening.

Before installation, it verifies the package bytes observed at the signature
step, checks for an active local publisher persona, parses without executing,
lists executable files, and keeps runtime safety unevaluated. On Linux, fresh
install uses one sealed package descriptor for proof verification, inspection,
extraction, and the receipt's package digest;
requires the candidate snapshot to match the package-derived tree plus local
receipt; pins the candidate and parent directories; and uses those parent
descriptors with `RENAME_NOREPLACE`. A successful return additionally proves
that the live inode is the candidate and its tree still matches. The official validator
is rooted at the pinned directory descriptor, and the candidate snapshot must
match before and after it. The reported status still says the content
observation was not continuous: same-user software could transiently change and
restore owner-writable files during validation. A Quo makes no Omarchy enable
call and does not edit enablement configuration, but it does request a shell
rescan. It cannot guarantee that concurrent `shell.json` changes never reference
or transiently load the plugin; that requires Omarchy cooperation through a
coordinated transaction or inhibit interface.

If exposure passed its exact postcheck but the initial shell rescan fails, A Quo
revalidates the pinned live candidate and private staging layout, then moves that
exact candidate back to the empty staging slot with a pinned-parent no-replace
rename. It then requests a restoration rescan and
rechecks the absent live target, restored candidate identity and tree, staging
mappings and mode, and unreferenced observation. A late publisher-authorization
finalization failure after exposure follows the same guarded restore path. Any
failed prerequisite, move, restoration rescan, or postcheck reports manual
attention and runs no recursive deletion. A verified filesystem rollback still
cannot prove that Omarchy never referenced or transiently loaded the plugin
before restoration.

The final namespace move is not inode-conditional: `renameat2` pins the parent
directories but resolves the source child name at syscall time. A same-user
swap in the remaining final-check-to-syscall window can expose a different tree.
The postcheck reports indeterminate instead of success. A final layout failure
after a successful initial rescan is likewise manual-attention state rather than
an automatic rollback. Fresh-install rollback
requires the exact pinned candidate at its final userspace check, but its own
no-replace rename has the same name-resolution window and its postcheck can
therefore discover that a wrong child moved. Update, rollback, and removal
child-name moves have the same underlying limitation.

Updates require the same persona and a strictly newer version. The Linux update
path swaps descriptor-pinned trees and rechecks both bounded snapshots after
rescan. A Quo also requires the installed manifest and receipt bytes used for
its own version/continuity decisions to match the pinned baseline. Its external
validator remains a before/after-bracketed pathname observation. A successful
update keeps the prior release at the reported private recovery path; verified
rollback keeps the rejected candidate there instead. Fresh install reports and
retains its private staging root after success. That root was originally used
for `package.tar.zst`, but after rescan A Quo checks neither whether that entry
still exists nor what bytes it names.
No automatic purge runs. Same-user software can modify retained material after
the command returns. Fresh-install rollback is a bounded in-process compensation,
not a durable transaction: intent journaling, parent-directory `fsync`, and
restart recovery are unfinished. Candidate extraction remains pathname-based beneath
same-user-writable staging: final snapshot verification rejects a substituted
result, but descriptor-relative extraction is still needed to contain
intermediate side effects.

Productisation is now bounded by a shared
[package and support contract](docs/PACKAGING.md), a candidate
[plugin-risk integration design and referenced-record parser](docs/PLUGIN-RISK.md), an exact
[revision-pinned corpus baseline](docs/OMARCHY-CORPUS.md), and
[trusted-consent accessibility requirements](docs/ACCESSIBILITY.md). These are
design inputs, not claims that an installable package, pre-install scanner
integration, accessible approval surface, or complete real-plugin matrix exists
yet. Plug & Prejudice owns behavioural scanning and its native report; A Quo will retain
and bind that report to exact signed bytes, apply local policy, obtain trusted
consent, and install the same bytes. The projects have the same owner, so this
is a useful process/privilege separation, not independent security review.
Provider-specific parsing stays in the optional adapter. A future second
reviewer keeps its own native report and attribution; disagreements are shown
separately rather than averaged into a safety result.

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
expectations. The low-level direct recovery command remains available, while
the bounded recovery-transition ceremony described below adds
participant-local consent. Routine `transition-request` can continue after an
explicitly committed recovery; see
[Portable persona continuity](docs/CONTINUITY.md).
Omit the expected-head pair when only a root pin is available; A Quo then calls
the result the key at the supplied chain tip and explicitly says that newer or
competing history may have been withheld.

Coordinate one short-lived recovery transition with the three current
prototype commands:

```sh
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-transition-ceremony-start --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-transition-ceremony-respond --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-transition-ceremony-assemble --help
```

`start` and `assemble` do not mutate the live persona. Each Linux participant
runs `respond` with the complete request and pins they obtained independently;
the private daemon derives whether that key is a recovery authority or the
exact successor and obtains direct local consent. The assembled proof still
requires a separate `recovery-transition-commit` or
`backup-activate-recovery`. First use must finish strictly before the signed
ceremony expiry. Exact replay of an already committed or sealed result may
succeed later because it grants no new authority and performs no signer I/O.
See [Persona continuity, backup, and recovery](docs/KEY-RECOVERY.md) for the
full command contract and limitations.

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
Archive activation itself remains a low-level authority-adoption operation; it
accepts either compatible low-level recovery evidence or an assembled ceremony
proof. A ceremony proof must be unexpired on first activation, while exact
replay of its already sealed receipt may succeed after expiry. Neither path
proves that participants were independent people or devices, that the pins
were independent or fresh, that no sibling or newer branch was withheld, legal
identity, or signed-material safety.

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

The terminal-hydration assurance suite additionally proves that changing any
one of the independently supplied root, final terminal-head, or latest-policy
pins after sealing produces a read-only conflict while preserving the exact
receipt, retained archive, live projection, audit history, and zero-authority
disposition. A separately threshold-signed terminal leaf issued later than the
trusted destination hydration time remains importable and inspectable as
evidence, but materialization fails before any projection and the quarantine
survives reopen. These are regression results for the existing bounded model,
not trusted-time, pin-independence, external-review, or production-readiness
claims.

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
  continuity recovery-transition-ceremony-start --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-transition-ceremony-respond --help
mise exec -- cargo run -p a-quo-cli -- \
  continuity recovery-transition-ceremony-assemble --help
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

Inspect or observe, then explicitly install, update, or remove an A Quo-managed
Omarchy release:

```sh
mise exec -- cargo run -p a-quo-cli -- omarchy inspect plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json

mise exec -- cargo run -p a-quo-cli -- omarchy observe-reference PLUGIN_ID \
  --json

mise exec -- cargo run -p a-quo-cli -- omarchy install plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json --yes \
  --accept-behavioral-analysis-not-run

mise exec -- cargo run -p a-quo-cli -- omarchy update plugin-v2.tar.zst \
  --proof plugin-v2.tar.zst.a-quo-proof.json --yes \
  --accept-behavioral-analysis-not-run

mise exec -- cargo run -p a-quo-cli -- omarchy uninstall PLUGIN_ID --yes
```

`observe-reference` is read-only and fail-closed. Its point-in-time JSON names
the plugin ID, `referenced` or `not_referenced`, `user` or `system_default`, and
the SHA-256 of the exact raw configuration bytes parsed. Invalid, oversized,
unsafe, or unmodelled configuration produces an error rather than a reassuring
answer. It does not reveal `shell.json` or establish runtime enablement or load
state.

`--yes` confirms the operation. Install and update additionally require the
separate acknowledgement that no behavioural reviewer analysed what the plugin
may do. Add `--json` to install, update, or uninstall for the corresponding
machine-readable outcome; it explicitly retains
`behavioral_analysis: not_run`, `trusted_consent: not_run`, and
`runtime_safety: not_evaluated`. A successful Linux install reports its retained
mode-0700 staging path, states that staging remains, and explicitly says no disk
purge ran. Once the
initial staging identity has been recorded, failures report the original cause
plus a revalidated path or last recorded device/inode when the path changed. A
failure before that identity capture says the recorded path is unconfirmed and
unsafe to purge without inspection. A verified fresh-install rollback reports
the exact candidate restored under retained staging and no live target; a
changed target, configuration uncertainty, occupied restore slot, failed
restoration rescan, or failed postcheck reports manual attention instead. On a
successful Linux update,
the command reports the retained prior release. Authorization refusal before
exchange also retains the candidate. If rollback succeeds, the command reports
the rejected candidate in recovery; if identity, bytes, modes, mappings, or the
restore rescan cannot be verified, it reports manual attention instead of a
false success. These statements describe a tree when it was checked, not a
permanently immutable backup.

The repository also contains a guarded, one-shot evaluator for this installed
core lifecycle. Its general non-mutating contract is
`mise run installed-omarchy-core-lifecycle-contract`, and a narrower
`scripts/test-installed-omarchy-core-preconsented-contract.sh` contract protects
the joined handoff branch. The armed task has two explicit modes. Its original
standalone mode uses installed `/usr/bin/a-quo` to create a disposable persona,
directly sign and verify v1 and v2, inspect, install, update, refuse a downgrade,
and remove. It does not use the signing daemon or trusted consent. Its joined
mode instead consumes the exact retained public persona and two proofs produced
by the installed consent evaluator; it creates no key or proof, verifies both
exact packages and proofs, installs v1, updates to v2, refuses the v1 downgrade
with an unchanged final managed-tree digest, and uninstalls v2 into retained
quarantine. Neither mode runs a behavioural provider or scanner or performs an
Omarchy enable action. No armed mode has produced clean-system evidence.

The joined path now has an exact inert v1/v2 fixture source pair and a
deterministic offline builder contract. Both packages carry the synthetic
plugin ID `aquo.test.joined-lifecycle`, have no entry points or executable
files, and are reconstructed from separate subtrees of exact A Quo source
commit `54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04`. The contract builds each
package twice from a local bare repository and pins package SHA-256 values
`2141fc8de82f40ac6a44b412e640846667b0cc78fd7b83280d157c24f87eaa71`
for v1 and
`806966a0bf27e902fc1e059c2a7004c72afcce085039c568c4ac5e17fead130a`
for v2. Run it with `mise run omarchy-joined-lifecycle-fixture-contract`.
An opt-in clean-tree build is:

```sh
mise run omarchy-joined-lifecycle-fixtures -- \
  /absolute/path/to/a-quo.git \
  /absolute/path/to/new-output-root
```

The resulting six-file bundle is namespaced to the frozen AArch64 v2 target
and records its profile ID, architecture, exact source subtrees, observations,
checksums, and conservative nonclaims. It is unsigned, unpublished, and has
not been behaviourally analysed or safety-evaluated. Its co-located checksum
file detects accidental or unreviewed changes relative to that bundle but is
not an authentication root. No package bytes are committed. The separate
immutable lock
`a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock` now closes the exact
selection portion of target input class 10 by binding these two fixtures, both
old/new A Quo packages, the bridge, consent and core evaluators, package
verifier, target resolver, and AArch64 profile. The offline verifier accepted
all ten caller-supplied mode-`0400` inputs from sealed snapshots against lock
commit `f1608a1c90e667644e936bc688f766e911c18262`, lock SHA-256
`c7520d646232f47c8990a04eb9cd2992c2ffba204843223f6e107b138b02d545`,
and policy commit `0e1fcb40c8b0d2e160ca8c139f4a5b6efb9a7400`. The lock is exact-byte
selection only: external authentication and durable retention remain absent,
and it grants no build, evaluator, package-manager, lifecycle, safety,
clean-system, or AArch64-gate authority. Nine target input classes remain if
this lock is adopted.

A guarded package-lifecycle bridge composes the consent and preconsented-core
evaluators with real host Pacman transactions. Before its network-namespace
probe, root lock, temporary root, mutation marker, or first Pacman command, it
now requires the committed class-10 lock and a root-owned mode-`0700` directory
containing exactly its ten singly linked mode-`0400` inputs. It binds the lock
to a caller-supplied Git commit and SHA-256, binds six policy files to their
reviewed Git blobs at the policy commit, confines both package paths to that
directory, and rechecks the inventory and bytes at every existing static-input
boundary. Its non-mutating contract is
`mise run installed-a-quo-package-lifecycle-contract`; the armed task requires
root on a specially marked disposable native AArch64 Omarchy target, two exact
root-owned package archives with caller digest and ordered source-commit pins,
and exact v1/v2 fixture pins. It is designed to install the old package, upgrade
to the new one, run the installed daemon and direct-Wayland helper for a v1
decline followed by v1 and v2 approvals, retain the resulting public persona and
two exact proofs, consume that handoff during v1 install, v2 update, v1
downgrade refusal, and v2 uninstall to retained quarantine, remove A Quo while
preserving user evidence, and reinstall the new package.
The acknowledged destructive path has **never been run**. It leaves the newer
package and evaluator evidence installed on success and performs no automatic
reversal on failure; package, hook, or service state may be partial or
indeterminate. It does not test a package downgrade, interruption recovery,
source-to-binary provenance, package signatures, behavioural review, plugin
safety, or clean-system status. The approved prompts authorize signing the
exact v1 and v2 artifacts. Installation uses only the CLI acknowledgements, and
no secure-attention property is established for that decision. Accordingly,
the intended outer evidence says `trusted_signing_consent_tested: true` and
`trusted_installation_consent_tested: false`. Joined rollback-failure and
interruption paths are not exercised. See the
[guarded bridge contract](docs/PACKAGING.md#guarded-real-pacman-package-lifecycle-bridge).

A separate interactive service/consent evaluator has a non-mutating contract
check at
`mise run installed-a-quo-consent-lifecycle-contract`; the same Mise task also
runs the narrow consent-handoff contract. Its armed task is
designed to use the stock installed user unit, daemon, fixed-path Wayland
helper, and one disposable OpenSSH file key. The operator must manually decline
the v1 signing prompt and then approve v1. When joined mode is requested, the
operator must additionally approve v2; the evaluator then removes the original
disposable key paths and signing locator while retaining the public persona
store, two exact proofs, and their strict handoff manifest.
Same-UID copying or access while the key existed is not excluded. The harness
contains no input-injection or auto-approval path, but input origin is not
machine-verifiable. The armed task has **not** been run, so it supplies no
service or consent result yet. In particular, it establishes no clean-system
or package-transaction result, accessibility or secure-attention property,
SSH-agent/FIDO/PIN behavior, Omarchy plugin lifecycle, behavioural analysis,
installation consent, plugin safety, or release readiness. See the
[installed evaluator contract](docs/PACKAGING.md#current-installed-serviceconsent-evaluator).

For fresh installs, `omarchy_manifest_validation` is
`passed_pinned_root_observation_not_content_continuous`: the official validator
returned success while rooted at the pinned candidate directory, and the
package-derived snapshot matched before and after. A Quo still cannot exclude a
transient change-and-restore of owner-writable descendants during the call.
For updates, the corresponding status is
`passed_path_observation_not_continuous`: the external validator returned
success, but A Quo cannot prove that a hostile same-user process did not briefly
change and restore its pathname during that call. A Quo's own installed-version
and receipt decisions are separately digest-bound to the pinned tree baseline.

Uninstall instead requires the plugin to be unreferenced and attempts to
restore the exact managed directory if the shell rescan fails; if restore is
blocked, it retains quarantine and reports manual recovery. These flags are not
trusted consent or safety overrides. A successful uninstall removes the plugin
from the live Omarchy namespace but deliberately retains the exact managed
directory inode at the reported recovery-quarantine path; automatic disk purge
is not yet implemented.

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
  bytes, signer paths, or keys. Recovery-participation prompts also omit the
  coordinator's local persona UUID and the participant's private signer
  locator.
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
- [Packaging and support contract](docs/PACKAGING.md)
- [Omarchy plugin risk evidence](docs/PLUGIN-RISK.md)
- [Owned Omarchy plugin corpus](docs/OMARCHY-CORPUS.md)
- [Accessibility and trusted consent](docs/ACCESSIBILITY.md)
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

On a clean source tree, `mise run release-scaffold` builds a local,
non-publishing three-binary scaffold with Rust dependency SBOMs, deterministic
source/build metadata, and verified checksums. It is not an installable package
or a release claim; see the [package contract](docs/PACKAGING.md).

On a clean native AArch64 Omarchy development host,
`mise run arch-package-skeleton` builds and verifies a passive Arch package
from the exact Git commit. The package contains the three binaries, disabled
per-user service, passive disable preset, empty optional-reviewer registry,
documentation, and license.
The task does not install the package or enable the service, and its output is
explicitly `PACKAGE-SKELETON-NONPUBLISHABLE`; clean-system lifecycle,
provenance, signing, accessibility, and release gates remain open.

Issues [#34](https://github.com/SurreptitiousFabric/a-quo/issues/34),
[#35](https://github.com/SurreptitiousFabric/a-quo/issues/35),
[#36](https://github.com/SurreptitiousFabric/a-quo/issues/36), and
[#37](https://github.com/SurreptitiousFabric/a-quo/issues/37) track a strictly
separate physical x86_64 evaluation lane. The closed package-target resolver
accepts exactly the existing AArch64 reference profile or the unarmed
`MacBookAir7,2` / official Omarchy 4.0.2-1 profile. Canonical `.PKGINFO arch`
and exact profile/namespace `xdata` bind every package tuple; x86 results cannot
satisfy an AArch64 gate. The x86 profile freezes an authority-none user-supplied
reconnaissance report, not a pristine or reproducibly pinned image, and still
requires a formal no-Mise read-only repeat.

The synthetic hostile contract for the direct-tool baseline collector and its
offline verifier is part of `mise run check`. It exercises only controlled
fixtures: no physical Intel observation has been captured, authenticated, or
accepted. On a separately authenticated checkout on that machine, the
collector must be invoked directly with `/usr/bin/bash --noprofile --norc`,
never through Mise; it writes only its receipt to standard output and requests
no Omarchy, package, service, plugin, or stage-6 mutation. The verifier binds a
captured receipt to the canonical profile and reviewed collector bytes but
deliberately reports `observation_authority=none`.

The authority-none hosted observation at exact source `cbbe29b6` produced a
real uninstalled x86_64 package and was reviewed only as ELF/NEEDED policy
input. The immutable lock
`a-quo-x86_64-needed-observation-cbbe29b6-v1.lock` binds its package and artifact
digests, profile/architecture/namespace tuple, `EM_X86_64`, interpreter
`/lib64/ld-linux-x86-64.so.2`, and exact dynamic libraries. CLI and daemon need
`ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6`; consent adds
`libwayland-client.so.0`. This reviewed lock is not provenance, signature,
physical-target, native-hardware, or stage-4 evidence.

The closed resolver now accepts those exact x86 sets only when the canonical,
nonsymlink lock and its verifier have the reviewed hashes. Normal package
verification is therefore available for this tuple, while
`--observe-unconfirmed-needed` is refused after policy acceptance. The original
`x86-package-needed-observation.yml` is historical and dispatches only at exact
`cbbe29b6`; its full hostile suite is replayed from that immutable Git snapshot.
The new manual `x86-package-static-acceptance.yml` reuses the pinned Arch,
Mise/Rust, non-root, network-none Docker boundary and runs the unchanged normal
builder and package verifier. Exact run `33456949816` at commit `ee47d7f1`
produced accepted artifact `9781997778`; its raw ZIP SHA-256 is
`15e24d068cd31b2de8cd23730303b5ad95a5d534d96c76076ddc015558d34f75`
and its uninstalled x86_64 package SHA-256 is
`75db0ad706aac8c69fefa29c0d27029b80796d665f452e296d0baae09ac25e11`.
All four retained ledgers replay after download. This completes only hosted
stage-4 static acceptance, not provenance, lifecycle, physical-target, native
hardware, AArch64, or stage-6 evidence.

The immutable F1 lock now binds that exact run, artifact, ZIP, package,
profile, architecture, namespace, and nonclaims. The manual
`x86-package-isolated-lifecycle.yml` defines stage 5 for a distinct descendant
F2: the raw F1 ZIP is downloaded by exact ID into root custody, then a
five-mount, UID/GID-1001, network-none container builds and statically verifies
F2 and invokes the existing upgrade harness unchanged. Its private alternate
fakeroot/libalpm sequence is install F1, upgrade to F2, remove, and reinstall
F2. The retained F2 builder/verifier receipt and lifecycle receipt bind the
profile and architecture and keep real-system, physical-target, cross-profile,
AArch64, and stage-6 claims false. The non-mutating hostile contract is part of
`mise run check`. After rejected run `33462058642` failed closed before
container creation because Cargo acquisition populated the lifecycle target,
the acquisition target was separated and the repair passed the full regression
suite. Exact run `33463360533` at commit `3f2d82e` then produced accepted
artifact `9784174842`; its raw ZIP SHA-256 is
`5bfe9222af422de71ec6b87354681b47bd9775bb1959ee6dcfc5bb2f73b62cd3`
and its F2 package SHA-256 is
`f10a96be2d5c7281cf9399fa92eecc09abe100b8dbdb60153a3ffa8e9cc361ab`.
All four ledgers and the exact pre-start container policy replay after
download. This completes only hosted, private alternate-root stage 5; it is not
physical Intel, real-Pacman, provenance, signature, clean-system, systemd,
Wayland, Omarchy integration, AArch64, or stage-6 evidence. No physical Intel
Omarchy state may be changed, and stage 6 remains unauthorized without a new
owner decision.

After that exact clean-HEAD package exists, run
`mise run arch-package-lifecycle-smoke -- PACKAGE COMMIT` for the bounded
fakeroot/libalpm install-remove simulation. It verifies package application,
inventory, simulated metadata, passive preset behavior, isolated binary
execution probes (`--version` and consent fail-closed), removal, and
preservation of synthetic user state. It deliberately does not
claim dependency resolution, real root ownership, a live user service, Wayland
consent, Omarchy integration, upgrade handling, or a clean system.

Given two package files, their caller-pinned SHA-256 values, and a named
ancestor/descendant commit pair, run:

```text
mise run arch-package-upgrade-smoke -- \
  OLD_PACKAGE OLD_SHA256 OLD_SOURCE_COMMIT \
  NEW_PACKAGE NEW_SHA256 NEW_SOURCE_COMMIT [PROFILE]
```

This performs an isolated fakeroot/libalpm old-install, new-upgrade, removal,
and new-reinstall sequence while checking the pinned package bytes, installed
files and metadata, disabled service state, and preservation of two synthetic
persona/plugin sentinel files. The named commits determine version ordering
and the verifier's structural and committed-asset policy; this does not prove
that the executable bytes were built from those sources. The non-mutating
`mise run arch-package-upgrade-contract` task checks the harness's fail-closed
seams. Neither task claims a signed or live system upgrade, downgrade refusal,
interruption recovery, dependency resolution, same-UID pathname-substitution
resistance, archive resource-exhaustion containment, Omarchy integration, or
clean-system evidence.

The non-mutating `mise run installed-a-quo-package-lifecycle-contract` is part
of normal checks. A separate task named `installed-a-quo-package-lifecycle` is
destructive, and its acknowledged path has never run; do not invoke it on a
development machine. Its
exact disposable-target, root-ownership, package, source, fixture, and failure
requirements are documented in the
[package contract](docs/PACKAGING.md#guarded-real-pacman-package-lifecycle-bridge).
The contract checks the joined v2 scaffold: installed-daemon decline for v1
followed by approvals for v1 and v2, an exact retained public handoff, core
verification of both packages and proofs, v1 install, v2 update, v1 downgrade
refusal with the same final managed-tree digest, v2 uninstall to retained
quarantine, and A Quo package remove/reinstall with preserved state.
Installation still relies only on CLI acknowledgements and establishes no
secure attention. It runs no
behavioural provider or scanner, establishes no plugin safety, and supplies no
clean-system runtime evidence. Its intended evidence names
those separate facts as `trusted_signing_consent_tested: true` and
`trusted_installation_consent_tested: false`.

`mise run omarchy-ubuntu-oci-input-lock-contract` exercises the closed lock,
external-pin, hostile-directory, sealed-snapshot, JSON, gzip, and DiffID
boundaries without image activity. On a cold development machine, its explicit
workspace-dependency prerequisite may fetch locked Rust dependencies; the
contract and verifier Cargo steps themselves are forced offline. Separate
`...-inspect` and `...-verify` tasks require a caller-supplied exact lock
repository, commit, path, and SHA-256. The verifier confirms the supplied SHA
against the bytes but does not authenticate Git hosting or the publisher. Full
verification accepts any local directory containing the four exact locked
objects; it does not require this machine's unsigned acquisition receipt. Its
sealed snapshots are dropped on exit. A future builder must extend and
integrate this same snapshot-and-semantic-verification path so it retains and
consumes the same descriptors, rather than verify and later reopen original
paths.
See the [input-lock contract](docs/PACKAGING.md#reviewed-ubuntu-oci-input-selection-lock).

The separate `mise run omarchy-builder-context-input-lock-contract` checks the
ten-file Omarchy builder-context selection without invoking Git or executing
the harness. Its inspect/verify tasks require an externally pinned lock tuple;
full verification accepts only an exact inert export, seals the files, and
recomputes both SHA-256 and Git blob IDs. This closes only input class 03's
exact selection. It does not retain the source, authorize a build, resolve the
other nine inputs, or produce an image. See the
[builder-context lock contract](docs/PACKAGING.md#reviewed-builder-context-and-harness-input-selection-lock).

`mise run omarchy-alarm-rootfs-input-lock-contract` separately checks the
class-04 ALARM rootfs lock. Its full verifier accepts exactly the locked
829,367,415-byte archive, 566-byte detached signature, and 5,304-byte
commit-pinned public key, copies each into a purpose-specific kernel-sealed
snapshot, and invokes root-owned `/usr/bin/gpg` with key retrieval disabled and
only inherited snapshot descriptors. It requires one exact RSA/SHA-512
`VALIDSIG` from primary fingerprint
`68B3537F39A313B3E574D06777193F152BDBE6A6`. That establishes neither trust in
the publisher nor current authorization, revocation status, freshness,
provenance, safety, retention, or build authority; the GPG binary itself is not
locked. The separate 1 GiB evidence cap does not change A Quo IPC's 512 MiB
artifact cap. See the
[ALARM rootfs lock contract](docs/PACKAGING.md#reviewed-alarm-rootfs-signature-and-key-input-selection-lock).

No system Rust installation is expected or supported by this repository.

## Status and license

Do not use this prototype as the sole authorization control for a high-risk
installation or as a replacement for an official Swiss or EU credential
wallet. Work is tracked on the
[Witness Me! Project](https://github.com/users/SurreptitiousFabric/projects/9).

Apache-2.0. See [`LICENSE`](LICENSE).
