# Roadmap

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
- dual-signed portable routine rotation (protocol/low-level CLI prototype complete;
  trusted consent pending);
- pre-authorized threshold recovery;
- append-oriented local audit history without secret payloads.

## 3. Omarchy integration

- `a-quo.identity` status and request interface;
- strict per-user consent IPC and immutable snapshot primitives (prototype complete);
- private serial signing daemon and signer-policy composition (prototype complete);
- isolated direct-Wayland consent process and closed child protocol (prototype complete);
- descriptor-based `request-sign` client with post-consent proof verification (prototype complete);
- domain-separated, short-lived DNS control consent and CLI flow (prototype complete);
- signed plugin release verification (prototype complete);
- staged, inspectable, atomic installation in a disabled state (prototype complete);
- same-persona, newer-version atomic updates with rescan rollback (prototype complete);
- permissions and runtime-risk reporting separate from publisher identity.

## 4. Public software supply chain

- Sigstore/Cosign release bundles;
- in-toto/SLSA build provenance;
- reproducible-build comparison where possible;
- TUF metadata for secure update and rollback rules.

## 5. Publishing, domains, and media

- detached artifact proofs for prose (prototype complete);
- exact-name DNS TXT domain-control proofs with bounded DNSSEC verification
  (prototype complete);
- optional HTTP origin-binding methods only if they preserve the distinction
  between DNS control, website control, and legal ownership;
- C2PA manifests for supported images and media;
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
