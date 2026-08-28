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
- strict non-secret persona metadata export/import (prototype complete);
- self-signed portable persona root with trusted single-key Linux consent
  (prototype complete);
- dual-signed portable routine rotation (portable protocol, low-level CLI, and
  trusted Linux consent/journal prototype implemented for newly journaled,
  routine-only histories; hardening, review, packaging, and older-history
  adoption pending);
- continuity tables introduced in schema v3, plus schema-v4 lifecycle ownership
  and replay guards, with atomic local key handoff and exact-proof retry
  recovery (prototype implemented; it is not an independent witness);
- optional independently supplied continuity-head checkpoints for detecting
  an older prefix or sibling branch relative to that checkpoint (prototype
  implemented; freshness and external witnessing remain pending);
- pre-authorized threshold recovery with old/new policy authorization and exact
  continuity checkpoints (protocol/low-level CLI prototype complete; trusted
  multi-party consent pending);
- append-oriented local audit history without secret payloads.

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
