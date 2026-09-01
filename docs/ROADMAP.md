# Roadmap

Delivery is tracked in the public
[Witness Me!](https://github.com/users/SurreptitiousFabric/projects/9) Project.
The normative meanings of Backlog, Design, Implementing, Prototype complete,
Hardening, External review, Done, and Acceptance evidence are defined in
[Maturity and acceptance evidence](MATURITY.md). The current issue-by-issue
classification and supporting evidence are recorded in the
[A Quo 0.x maturity audit](MATURITY-AUDIT.md).

## 1. Portable proof kernel

- hash arbitrary artifacts;
- create and verify versioned SSHSIG proof bundles;
- report what is proven and what remains unknown;
- publish format fixtures and tamper tests.

## 2. Persona and policy service

- separate keys and policies per persona;
- hardware-backed key enrollment;
- explicit local key rotation/compromise and historical verification (prototype complete);
- strict non-secret metadata-only persona backup v1, retained for compatible
  import (prototype complete);
- bounded evidence-only persona backup v2 with a self-contained signed root,
  recovery-policy chain, and mixed routine/recovery transition history,
  retained for compatible import; backup v3 adds an optional final terminal
  leaf and zero-current-authority lifecycle state. Internal reverification and
  quarantine-preserving re-export are a foundation. A non-mutating comparison
  gate for one archive per invocation has a bounded prototype under
  [#27](https://github.com/SurreptitiousFabric/a-quo/issues/27): it requires
  separately supplied exact root, effective-head, and explicit latest-policy
  expectations and reports exact, extension, divergence, or
  shorter/inconclusive without granting custody or authority. Its bounded
  acceptance is `Prototype complete` at public revision
  `57be5e25096070c667c7891a946ce4e3e2a4bef4`, with hosted check, audit, and
  fuzz evidence; multi-candidate selection and safe fork resolution remain
  pending;
- self-signed portable persona root with trusted single-key Linux consent
  (prototype complete);
- portable public root cards, digest-only pin URIs, typed observation records,
  and read-only comparison under
  [#3](https://github.com/SurreptitiousFabric/a-quo/issues/3). The bounded
  prototype supports deterministic JSON, accessible text, printable static
  HTML/QR, explicit TOFU/same-channel/user-reported out-of-band provenance,
  and a two-step first-contact CLI that writes nothing until the exact root
  digest is accepted. It internally verifies the signed root and reports
  evidence dimensions separately; a card or pin grants no authority and
  establishes no legal identity, trusted time, current history, or artifact
  safety. The portable core formats and renderers are exercised on Linux,
  macOS, and Windows at exact public revision
  `1637cb7b55ee330a685e033cba311fb978b024ec`; packaging, assistive-technology
  validation, native product integration, broader platform file-I/O
  hardening, and independent review remain open;
- dual-signed portable routine rotation (portable protocol, low-level CLI, and
  trusted Linux consent/journal prototype implemented for newly journaled live
  histories, including routine rotation after a committed recovery; hardening,
  review, packaging, and older-history adoption pending);
- continuity tables introduced in schema v3, schema-v4 lifecycle ownership and
  replay guards, schema-v7 immutable policy/mixed-transition journals, the
  schema-v8 immutable terminal overlay/freeze guards, and schema-v9 sealed
  archive-materialization receipts. Schema v10 adds a narrowly guarded
  terminal-hydration insertion path that can project the exact imported
  terminal leaf only while its matching receipt is pending. Schema v11 binds a
  recovery-activation receipt to the exact recovery-proof bytes and permits its
  recovery result head only through the matching pending materialization, with
  atomic local key handoff and exact-proof retry recovery (prototype
  implemented; these schemas are not independent witnesses);
- optional independently supplied continuity-head checkpoints for detecting
  an older prefix or sibling branch relative to that checkpoint (prototype
  implemented; freshness and external witnessing remain pending);
- pre-authorized threshold recovery with old/new policy authorization and exact
  continuity checkpoints, append-only live policy recording, atomic
  recovery/compromise transition commit, exact committed-wrapper retry, and
  later routine rotation. One recovery transition can now use a bounded
  portable request/response ceremony with independently supplied pins, private
  Linux/direct-Wayland participant consent, deterministic assembly into the
  existing proof, signed expiry, first-use enforcement, and read-only exact
  replay after commit or materialization. Policy enrollment/update and terminal
  revocation remain sequential; packaging, accessible product UX, genuine
  independent-holder evidence, broader testing, and independent review remain
  pending;
- explicit-capability terminal no-successor revocation, atomic zero-authority
  commit, exact first-wrapper replay, and evidence-only v3 preservation
  (bounded prototype implemented; trusted ceremony, independent review,
  witnessing, and product UX pending);
- staged archive materialization under
  [#26](https://github.com/SurreptitiousFabric/a-quo/issues/26). Direct
  activation after fresh current-key custody
  ([#29](https://github.com/SurreptitiousFabric/a-quo/issues/29)) now has a
  bounded CLI/store prototype: it requires exact archive/root/head/policy/
  current-key expectations, retains the immutable source, atomically seals the
  exact live projection and signer binding, authenticates later
  binding-history suffixes,
  and provides signer-free exact replay. Its bounded acceptance is `Prototype
  complete` at public revision
  `57be5e25096070c667c7891a946ce4e3e2a4bef4`, with hosted check, audit, and
  fuzz evidence; product and contention hardening and independent review remain
  separate later gates. Zero-authority terminal hydration
  ([#28](https://github.com/SurreptitiousFabric/a-quo/issues/28)) now has a
  bounded CLI/store prototype: exact archive/root/final-head/policy pins,
  complete terminal reverification, one transactional frozen projection, a
  retained source archive, sealed read-only replay, and no key, signer,
  custody, recovery exercise, or reactivation route. Its bounded acceptance is
  `Prototype complete` at public revision
  `9cef13b89c88d29aefeda0f91c337f52da6d3c0d`, with hosted check, audit, and
  fuzz evidence. Product/contention hardening and independent review remain
  later gates. The path-specific P3 assurance additions in
  [#31](https://github.com/SurreptitiousFabric/a-quo/issues/31) and
  [#32](https://github.com/SurreptitiousFabric/a-quo/issues/32) are implemented
  at exact public revision `b2dab9a7b3c9479b781a22a86f19c8a115c7d190`:
  post-seal root/head/policy substitutions preserve the exact frozen state,
  and a valid future-issued terminal leaf remains inspectable quarantine while
  materialization fails before mutation. These tests do not broaden #28 or
  establish trusted time, independent pins, or production readiness. Recovery
  activation through one exact authorized transition plus fresh successor
  custody ([#30](https://github.com/SurreptitiousFabric/a-quo/issues/30)) now has
  a bounded CLI/store prototype. It requires exact archive/root/source-head/
  latest-policy expectations, retains the immutable source, never authorizes the
  lost archived tip, atomically appends the exact recovery proof and successor
  binding, and provides signer-free exact replay. Its bounded acceptance is
  `Prototype complete` at public revision
  `9dc67c6c949e7313adeefe1fedfee8a8c5f3a87a`, with hosted check, audit, and
  fuzz evidence. Product/contention hardening, trusted multi-party consent, and
  independent review remain later gates. No mode yet resolves an existing live
  fork;
- append-oriented local audit history without secret payloads.
- safe cross-transaction reuse of native live-journal verification and a
  request-wide crypto-work budget; one-pass/incremental verification and the
  64 MiB aggregate live proof-byte preflight (including reserved append bytes)
  are implemented. Candidate signatures can cross the local transaction
  boundary in an opaque receipt, while safe reuse of the stored-prefix result
  and coordination across separate daemon, CLI, and Omarchy checkpoints remain
  pending;

## 3. Omarchy integration

- `a-quo.identity` status and request interface;
- strict per-user consent IPC and immutable snapshot primitives (prototype complete);
- private serial signing daemon and signer-policy composition (prototype complete);
- isolated direct-Wayland consent process and closed child protocol (prototype complete);
- descriptor-based `request-sign` client with post-consent proof verification (prototype complete);
- domain-separated, short-lived DNS control consent and CLI flow (prototype complete);
- domain-separated persona-root consent and client re-verification (prototype complete);
- domain-separated routine-transition consent, dual-signature verification,
  and atomic journal commit before proof release (prototype implemented);
- domain-separated recovery-transition participation over the private Unix
  socket, with complete portable-request reverification, independently supplied
  root/policy/head pins, derived participant roles, direct-Wayland consent, and
  a sealed response (bounded Linux prototype; assembly and commit are separate);
- signed plugin release verification (prototype complete);
- fail-closed, read-only observation of the exact accepted persisted Omarchy
  configuration for one plugin ID, including user/default source and raw-byte
  SHA-256 without returning the configuration contents (implemented; this is a
  point-in-time file observation, not evidence of shell application,
  enablement, load state, or absence of a concurrent change);
- staged, inspectable, atomic no-replace namespace move without an A Quo enable call
  (bounded Linux prototype implemented: proof verification, archive inspection,
  extraction, and the receipt package digest share one sealed input; the
  package-derived candidate plus local receipt is snapshot-bound; plugins,
  staging, and candidate roots are pinned; validator root redirection is
  prevented during validation; exposure uses pinned parent descriptors and
  no-replace; successful return requires post-rescan identity and tree checks;
  staging is retained rather than recursively purged; and a first-rescan or late
  authorization-finalization failure after successfully postchecked exposure
  attempts an exact no-replace restore to staging, restoration rescan, and
  post-verification while the candidate remains exact, followed by a fresh
  configuration-reference observation.
  Standalone-inspection parity, durable intent/restart recovery, safe purge,
  descriptor-relative extraction containment, validator isolation,
  inode-conditional child moves,
  and race-free unreferenced exposure remain open);
- bounded Linux same-persona, newer-version updates with one kernel-sealed
  proof/inspection/extraction/receipt input, a package-derived candidate-tree
  binding, snapshot-digest-bound installed manifest/receipt decisions,
  pinned-parent exchange with post-rescan identity/tree verification, retained
  prior release on success, and retained rejected
  candidate after verified rollback. Update input is opened no-follow and
  nonblocking, copied through a hard size bound, and staging is retained from
  creation rather than recursively deleted by pathname (prototype implemented;
  guarantees are point-in-time; fresh-install and update rollback remain
  separate bounded paths and neither makes child moves inode-conditional;
  standalone-inspection sealed-input parity, durable
  intent and restart recovery,
  parent-directory `fsync`, safe purge, and Omarchy-owned reference/load
  coordination remain open; descriptor-relative extraction containment and
  external-validator isolation are also open);
- managed-only, unreferenced pinned-parent namespace removal with post-verified
  rollback when unobstructed, fail-closed retained quarantine
  otherwise, retain-on-panic recovery, and no recursive purge of mutable paths
  (bounded Linux prototype; child entries remain name-resolved at each syscall,
  so inode-conditional moves, durable restart recovery, safe purge, and
  Omarchy-owned reference coordination remain open);
- one shared #7/#25 package and support contract with a complete pinned
  Omarchy 4 aarch64 walking-skeleton journey
  ([design contract and passive native package skeleton](PACKAGING.md)); the
  exact package payload/unit/empty-registry builder and verifier are now
  implemented, along with an ancestry-ordered development version, passive
  disable preset, bounded fakeroot/libalpm install-remove smoke, a separate
  caller-digest-pinned old-to-new/remove/reinstall transition smoke with a
  synthetic hostile contract, and a guarded one-shot installed-core lifecycle
  evaluator with passing general and preconsented-branch non-mutating contract
  checks. Its legacy standalone mode still creates a disposable persona and
  directly signs the v1/v2 fixtures for install, update, downgrade-refusal, and
  removal coverage. Its new joined mode instead consumes an exact retained
  public persona/two-proof handoff, verifies both exact packages and proofs,
  installs v1, updates to v2, refuses a v1 downgrade with the same final
  managed-tree digest, and uninstalls v2 into retained quarantine. Recovered v1
  and quarantined v2 full-tree digests must match their pre-move states; these
  final-state comparisons do not exclude transient mutation or byte-identical
  replacement. A guarded real-Pacman bridge now composes exact old install, new
  upgrade, the installed daemon's operator-
  observed v1 decline followed by v1 and v2 signing approvals, strict public
  handoff, preconsented v2 core evaluation, removal with retained user evidence,
  and new reinstall. Separate consent-handoff, preconsented-core, and outer-
  bridge contracts cover this joined path; no armed path has run. The outer
  bridge cross-checks both exact packages and proofs, the manifest, persona,
  fingerprint, and
  retained-store digest between the consent and core evidence, while explicitly
  leaving the same-UID handoff origin unauthenticated. It also requires both
  package verifier receipts and all nested/outer evidence to carry one exact
  frozen AArch64 v2 target tuple, rejecting duplicate overrides,
  cross-profile mixing, and any claim that x86_64 evidence satisfies that
  gate before the first Pacman mutation. This remains non-mutating source-
  contract evidence. The core alone does not
  establish trusted consent. Installation uses only CLI acknowledgements and
  establishes no secure attention. The intended joined evidence distinguishes
  `trusted_signing_consent_tested: true` from
  `trusted_installation_consent_tested: false`. The transition smoke is
  isolated and performs no source-to-binary provenance, same-UID substitution,
  archive-resource-containment, signature, dependency, scriptlet, live-service,
  downgrade, interruption, Omarchy, or clean-system test. Frozen v1
  and v2 target profiles remain the unchanged AArch64 reference gate. The
  repository now owns an exact inert same-ID increasing-version fixture pair,
  and its subtree-aware raw-Git builder contract reproduces both unsigned
  packages byte-for-byte while rejecting path/tree mixing and escalated
  evidence claims. A separate immutable class-10 lock now binds those exact
  fixture bytes with the old/new A Quo packages, six reviewed policy files, and
  the unchanged AArch64 profile. Its offline verifier accepted all ten retained
  inputs from sealed snapshots at lock commit `f1608a1c`, lock SHA-256
  `c7520d64...`, and policy commit `0e1fcb40`; the bridge requires and rechecks
  that closed selection before any mutation boundary. The lock supplies no
  external authentication or durable retention and grants no arming,
  lifecycle, safety, clean-system, or reference-gate authority. Nine target
  input classes remain if it is adopted. A
  separate [#34](https://github.com/SurreptitiousFabric/a-quo/issues/34) /
  [#35](https://github.com/SurreptitiousFabric/a-quo/issues/35) /
  [#36](https://github.com/SurreptitiousFabric/a-quo/issues/36) /
  [#37](https://github.com/SurreptitiousFabric/a-quo/issues/37) x86_64 lane now
  has an authority-none unarmed physical profile, a closed two-entry package
  mapping, a direct-tool baseline collector/offline verifier with a synthetic
  hostile contract, and cross-profile transition refusal. An authority-none
  hosted run produced a real uninstalled x86 package and exact ELF/NEEDED facts;
  the reviewed immutable lock now binds those facts as x86 policy input while
  preserving the original nonaccepting workflow and hostile suite at exact
  `cbbe29b6`. The separate accepted-static workflow ran at exact
  `ee47d7f1` and artifact `9781997778` is accepted only as uninstalled hosted
  stage-4 x86 evidence. Its immutable F1 lock feeds a newly defined manual
  stage-5 workflow: root-custodied F1 plus a distinct descendant F2 enter the
  unchanged private fakeroot/libalpm install-upgrade-remove-reinstall harness
  in a five-mount network-none container. The non-mutating hostile contract is
  in `mise run check`. A first run failed closed before container creation and
  was rejected; after separating dependency acquisition from the lifecycle
  target, exact run `33463360533` at `3f2d82e` completed all four private
  transactions and produced accepted artifact `9784174842` with raw ZIP
  SHA-256 `5bfe9222af422de71ec6b87354681b47bd9775bb1959ee6dcfc5bb2f73b62cd3`.
  Hosted stage 5 is therefore closed only for those exact alternate-root bytes
  and nonclaims. No authenticated physical receipt or physical-target evidence
  exists. Stage 6 still requires a later owner decision. The same
  frozen v1 and v2 target
  profiles now have separate candidate-only boundaries for the
  signed Omarchy bootstrap assets and the exact Ubuntu ARM64 OCI descriptor
  chain. The latter has a no-network synthetic/hostile contract. One opt-in
  run failed closed on Docker's current exact CloudFront redirect and remained
  `INCOMPLETE`; after a narrowly tested exact-host correction, a second fresh
  run acquired and separately reverified all four objects and 28,896,414
  bytes. Its ignored 27-line receipt retains `authority=none`. A separate
  committed four-object input-selection lock and Linux Rust verifier now bind
  an externally expected lock tuple to the unchanged v2 profile, pin a flat
  caller-supplied object set without following links, copy each identity-checked
  descriptor once, and perform exact
  hash, descriptor-chain, strict-JSON, bounded-gzip, and DiffID verification
  from sealed snapshots. The receipt is optional context; the lock does not
  publish or durably retain bytes, authorize a build, or make the target
  runnable. A separate candidate-only class-02 boundary now runs APT update,
  simulation, and download-only operations in the locked OCI root under a
  private non-root Bubblewrap namespace. Two ignored, same-host complete runs
  retained byte-identical sets of 19 snapshot indexes and 93 package archives;
  offline verification bound 122 objects and matched 93 solver install records
  to those archives without any package installation or VM. They retain
  `authority=none`, provide no independent reproduction, and do not close
  class 02: the base ports archive and effective main snapshot archive are not
  established equivalent, and no reviewed lock, publisher authentication,
  trusted time, freshness, independent closure proof, durable retention, build
  authorization, safety, or final image exists. A separate reviewed class-03
  lock now binds the ten exact Omarchy
  source blobs used by the current Asahi fresh-VM harness and verifies
  seventeen dependency-literal routes from sealed snapshots of an externally
  pinned, caller-supplied inert export. Its verifier invokes no Git, network,
  harness, container, package-manager, mount, or VM operation. It closes only
  builder-context exact selection: the frozen profile retains its historical
  ten unresolved-input lines and would still have nine unresolved input
  classes if the lock were adopted. It provides no durable retention, build
  authorization, runnable image, source-to-image provenance, freshness, or
  safety claim. A separate class-04 lock now binds one exact 829,367,415-byte
  ALARM rootfs archive, detached signature, and commit-pinned public key to the
  unchanged v2 profile. Its Linux verifier copies exact descriptors into
  class-specific sealed snapshots, disables key retrieval, and requires one
  exact RSA/SHA-512 signature from the profile fingerprint. This closes only
  exact class-04 selection: GPG bytes, current publisher authorization and
  revocation, trusted time, freshness, provenance, safety, durable retention,
  build authority, and the other nine inputs remain unestablished. This
  created no image, extracted rootfs, package transaction, mount, or VM. The
  separate class-07 lock now binds the unchanged profile to the exact retained
  non-authoritative APT receipt and manifest plus Ubuntu package
  `qemu-efi-aarch64_2024.02-2ubuntu0.9_all.deb`. Its offline Linux verifier
  seals all three inputs, checks the Debian ar and bounded zstd/tar structure,
  and verifies the exact CODE symlink and two 64 MiB AAVMF files consumed by
  the harness without extraction or execution. This closes only exact
  class-07 selection. It does not close class 02: original-ports versus
  snapshot-main archive equivalence and independent APT signature replay are
  absent. Publisher/current authorization, trusted time, freshness,
  source-to-firmware provenance, safety, durable retention, build authority,
  VM execution, and the other nine historical inputs remain unestablished.
  Classes 03, 04, 07, and 10 remain separate evidence and are not aggregated
  into an armed or runnable profile. The
  installed-core, real-Pacman-bridge, and service/consent armed tasks have not
  run on a marked disposable target. The service/consent evaluator is designed
  for an operator-observed v1 decline followed by v1 and v2 approvals using one
  OpenSSH file key;
  it has no input-injection or auto-approval path, and input origin is not
  machine-verifiable. In joined mode it unbinds the signing locator and removes
  the original disposable key paths while retaining the public persona store
  and exact two-proof v2 handoff; same-UID copying or access while the key
  existed is not excluded. This is signing consent for the exact v1 and v2
  bytes, while installation consent remains CLI acknowledgements without secure
  attention. It has produced no runtime evidence and does not cover
  accessibility, agent/FIDO/PIN behavior, behavioural analysis, or plugin
  safety. No behavioural provider or scanner runs. An executed real package
  install/upgrade/remove/reinstall, package downgrade and interruption
  lifecycle, joined plugin rollback-failure behavior, clean-system evidence,
  provenance, release signing, publication, and release readiness remain
  pending. Signed does not mean safe;
- an exact-snapshot-bound plugin-risk integration that keeps artifact,
  publisher, structure, Plug & Prejudice analysis, review, and local policy
  separate
  ([corrected design and Stage-0 shape/binding parser](PLUGIN-RISK.md)); closed
  schemas, bounded exact-JCS parsers, derivable internal/cross-record checks, a
  seeded parser fuzz target, and one blocked/indeterminate golden update now
  cover publisher/structure/delta/policy/policy-result/assessment record
  shapes. This is exact-subject, structure, policy, and binding work only. The
  candidate surface now treats native reports as opaque attachments and has no
  A Quo capability, observation, evidence, or coverage model. Concrete Plug &
  Prejudice report validation and subject binding, scanner provenance, stream
  interoperability, comparison, sustained fuzz evidence, schema freeze,
  eligibility decision, and trusted install prompt remain pending;
- Plug & Prejudice as the authoritative owner of its behavioural native report
  and intended first supported optional adapter, separately executed and
  never given signing, consent, policy, or installation authority. A Quo core
  remains useful without it, while behavioural analysis is explicitly
  unavailable and local policy blocks or requires warned consent. Its
  published installed-plugin scanner exists;
  sealed exact pre-install snapshot support is tracked in
  [Plug & Prejudice #31](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/31).
  Same-owner separation is operational, not organizationally independent
  review. Provider-specific parsing belongs in the provisional
  `a-quo-provider-plug-and-prejudice` package; core retains opaque native-report
  bindings. A future real reviewer receives its own adapter and attribution,
  and disagreement is never averaged into safety;
- a strict six-revision source registry for three representative plugins and a
  real Frame update/refusal family, plus a deterministic unsigned raw-Git-object
  package-builder prototype, offline synthetic regression, and frozen
  package/tar SHA-256 observations from two byte-identical same-host cohort
  builds ([corpus baseline](OMARCHY-CORPUS.md)); package publication,
  independent-environment reproduction, proofs, hostile variants,
  scanner-recursion package, and clean-system results are still missing; and
- an inventory and security/accessibility contract for every current trusted
  prompt ([requirements baseline](ACCESSIBILITY.md)); screen-reader semantics,
  complete reflow, and real assistive-technology validation remain pending.

## 4. Public software supply chain

- offline standardized Sigstore/Cosign v0.3 bundle verification with explicit
  trust root and exact certificate identity policy (prototype complete);
- authenticated in-toto Statement v1 and SLSA provenance reporting without
  unearned build-level claims (prototype complete);
- a non-publishing local scaffold for three Linux binaries, per-binary Rust
  dependency SBOMs, deterministic source/build metadata, and verified
  checksums, plus a clean-exact-commit native AArch64 package skeleton with a
  closed payload verifier and a simulated install-remove smoke (implemented;
  the package skeleton is non-hermetic and non-publishable, and provenance,
  complete native SBOM, independent rebuild comparison, clean-system lifecycle
  evidence, signing, and publication are explicitly not produced);
- a separate x86_64 Omarchy 4.0.2-1 package-target contract with exact
  profile/architecture/namespace binding and fail-closed NEEDED observation
  mode, fixed non-accepting bundle verifier, and manual pinned hosted execution
  path (source contracts implemented; the workflow has not run, and real
  package production, static acceptance, isolated lifecycle execution, and
  physical-machine evidence remain open and cannot satisfy the AArch64
  reference gate);
- CI creation and publication of A Quo's own Sigstore release bundles;
- per-project builder, source, build-type, and external-parameter expectations;
- reproducible-build comparison where possible;
- TUF metadata for secure update and rollback rules.

## 5. Publishing, domains, and media

- detached artifact proofs for prose (prototype complete);
- exact-name DNS TXT domain-control proofs with bounded DNSSEC verification
  (prototype complete);
- optional HTTP origin-binding methods only if they preserve the distinction
  between DNS control, website control, and legal ownership;
- offline verification of embedded local C2PA manifests in an isolated Linux
  worker (prototype complete; certificate trust, CAWG validation, and signing
  pending);
- sidecar proofs for formats that cannot safely embed provenance.

## 6. Credential bridges

- blockchain account and DID adapters without making a chain mandatory;
- Swiss swiyu and EU Digital Identity Wallet presentation hand-offs;
- selective-disclosure requests mediated by the official wallet;
- clear issuer, validity, revocation actor, time, and policy reporting.

Regulated credentials remain in the authorized wallet unless standards,
security review, and law make another custody model appropriate.

## 7. Other platforms

- package the same core for other Linux distributions;
- add native consent and keystore adapters for macOS and Windows;
- keep proof formats and policy semantics interoperable across platforms.
