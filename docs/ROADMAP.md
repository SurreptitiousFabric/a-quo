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
  later routine rotation (prototype implemented; trusted multi-party consent
  pending);
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
  later gates; path-specific P3 assurance additions are tracked in
  [#31](https://github.com/SurreptitiousFabric/a-quo/issues/31) and
  [#32](https://github.com/SurreptitiousFabric/a-quo/issues/32). Recovery
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
- signed plugin release verification (prototype complete);
- staged, inspectable, atomic installation in a disabled state (prototype complete);
- same-persona, newer-version atomic updates with rescan rollback (prototype complete);
- permissions and runtime-risk reporting separate from publisher identity.

## 4. Public software supply chain

- offline standardized Sigstore/Cosign v0.3 bundle verification with explicit
  trust root and exact certificate identity policy (prototype complete);
- authenticated in-toto Statement v1 and SLSA provenance reporting without
  unearned build-level claims (prototype complete);
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
