# Roadmap

## 1. Portable proof kernel

- hash arbitrary artifacts;
- create and verify versioned SSHSIG proof bundles;
- report what is proven and what remains unknown;
- publish format fixtures and tamper tests.

## 2. Persona and policy service

- separate keys and policies per persona;
- hardware-backed key enrollment;
- explicit key rotation, compromise, recovery, and historical verification;
- append-oriented local audit history without secret payloads.

## 3. Omarchy integration

- `a-quo.identity` status and request interface;
- isolated GTK4/libadwaita consent process;
- signed plugin release verification;
- staged, inspectable, atomic installation in a disabled state;
- permissions and runtime-risk reporting separate from publisher identity.

## 4. Public software supply chain

- Sigstore/Cosign release bundles;
- in-toto/SLSA build provenance;
- reproducible-build comparison where possible;
- TUF metadata for secure update and rollback rules.

## 5. Publishing and media

- detached proofs for prose and website ownership challenges;
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
