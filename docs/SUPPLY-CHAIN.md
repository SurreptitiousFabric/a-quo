# Offline Sigstore and SLSA verification

**Status:** Linux/Omarchy verification prototype implemented. Signing,
trust-root updating, build-expectation policy, SLSA level assessment,
reproducible-build comparison, TUF update metadata, and other operating systems
are pending.

## What this proves

Run:

```sh
mise exec -- cargo run -p a-quo-cli -- supply-chain verify-bundle ARTIFACT \
  --bundle ARTIFACT.sigstore.json \
  --trusted-root trusted_root.json \
  --identity 'EXACT CERTIFICATE IDENTITY' \
  --issuer 'EXACT OIDC ISSUER'
```

The command accepts only the standardized Sigstore bundle media type
`application/vnd.dev.sigstore.bundle.v0.3+json`. It requires one explicit
local trusted-root snapshot and exact certificate identity and issuer strings.
It makes no network request.

A `verified` result establishes all of these facts for the exact artifact
SHA-256 and size in the report:

| Evidence | Meaning |
| --- | --- |
| artifact binding | The signed blob digest or an in-toto Statement v1 subject matches the artifact. |
| signature | The bundle signature is cryptographically valid. |
| certificate chain and SCT | The ephemeral signing certificate chains to the supplied root, was valid at the verified signing time, has code-signing usage, and its embedded certificate-transparency SCT verifies. |
| transparency log | The inclusion proof and signed checkpoint verify with the supplied Rekor key, and the log entry is consistent with the bundle. |
| signing time | A signed Rekor integrated time or RFC 3161 timestamp establishes the certificate-validation time. |
| signer policy | The verified certificate identity and Fulcio OIDC issuer exactly equal both command-line policy values. |

For DSSE, A Quo additionally requires exactly one signature, payload type
`application/vnd.in-toto+json`, and exact statement `_type`
`https://in-toto.io/Statement/v1`. Other signed DSSE payloads fail closed.

If the authenticated predicate type is
`https://slsa.dev/provenance/v1`, A Quo checks that the required v1
`buildDefinition`, `buildType`, `externalParameters`, `runDetails`,
`builder`, and `builder.id` shapes are present. It reports `builder.id` and
`buildType` as signed claims. It does not assign a SLSA Build level or decide
whether those values meet expectations. The current SLSA specification still
uses that stable v1 predicate URI across compatible minor revisions.

## Trust-root responsibility

The bundle is not allowed to choose its own trust anchor. `--trusted-root` is a
separate input and its SHA-256 is printed in every report. Obtain and update it
through a trusted, TUF-aware Sigstore or platform process, then transfer or pin
it through the channel appropriate to your threat model.

A Quo deliberately does not fetch or silently refresh trust material during
verification. This makes the verification reproducible and offline, but it
also means A Quo cannot establish:

- how the supplied root file was obtained;
- whether it is the intended root for this publisher or ecosystem;
- whether its snapshot is current;
- whether a key was revoked or rotated after the snapshot was obtained; or
- whether a newly signed bundle needs trust material newer than the snapshot.

Those limits are reported even after successful cryptographic verification.
An old root may verify historical evidence yet fail newer evidence after a
rotation. A malformed, unrelated, or insufficient root fails closed.

## Isolation design

Bundles and trusted roots are hostile parser inputs. They never enter
`a-quo-daemon`, the signing consent process, a wallet, or an Omarchy plugin
process.

On Linux the verifier:

1. opens the artifact, bundle, and trust root with `O_NOFOLLOW`, rejects
   non-regular files, and copies them into sealed memfds while hashing them;
2. caps the artifact at 512 MiB and each JSON input at 4 MiB;
3. discards the artifact bytes before crypto parsing and passes only its
   SHA-256 digest and size to the worker;
4. encodes the two JSON snapshots in a closed length-delimited frame, seals it,
   streams it to a hidden launcher, and requires the launcher to independently
   re-snapshot and match the frame digest and size;
5. validates fixed `/usr/bin/bwrap` and `/usr/bin/prlimit` executables as
   regular, executable, non-symlink, non-group/world-writable system files;
6. directly enters unshared user, PID, network, IPC, UTS, cgroup, and mount
   namespaces with no capabilities, disabled nested user namespaces, a
   read-only `/usr`, isolated `/proc`, `/dev`, and `/tmp`, and only the
   read-only input frame plus the already-open A Quo executable;
7. applies 45 wall seconds, 30 CPU seconds, 1 GiB address space, 64 file
   descriptors, 16 processes, no core dumps, and bounded output; and
8. accepts only a closed, versioned worker response containing bounded,
   control-free evidence fields or a closed failure code.

The parent applies the exact identity and issuer comparison again to the
verified worker result. A mismatch may report that the cryptography passed,
but the overall outcome remains `invalid`.

## Dependency and network policy

A Quo pins `sigstore-verify` 0.11.0 with default features disabled. TUF,
Rustls, and native-TLS client features are not enabled. The upstream Rekor and
TSA crates still unconditionally compile `reqwest` data/client code with only
its JSON and form features; A Quo never constructs those clients. This is
unnecessary code footprint, not a network authority: the worker has no network
namespace at the operating-system boundary. The dependency is isolated to the
CLI adapter and does not enter the daemon dependency graph.

The cryptographic path inherits `sigstore-verify`, `aws-lc-rs`, and the AWS-LC
C implementation. Process isolation reduces parser and network blast radius;
it does not independently prove those implementations cryptographically
correct.

The implementation uses a precomputed SHA-256 artifact digest supported by the
verifier. Blob bundles declaring another digest algorithm and key-hint bundles
without a certificate are rejected in this first slice. Certificate SCT
verification is mandatory; private Sigstore instances whose certificates omit
the public SCT need a separate explicit trust-domain policy rather than a
global skip switch.

Legacy Cosign bundles are not accepted. In particular, this avoids the legacy
verification path affected by
[`GHSA-fx35-mq7g-6g98`](https://github.com/sigstore/cosign/security/advisories/GHSA-fx35-mq7g-6g98).
The advisory states that standardized v0.3 bundles are not affected.

## What remains unproven

Even a fully verified report does not establish:

- that the signer or builder is trusted for this particular artifact;
- that `builder.id`, source, `buildType`, or external parameters match an
  independently configured expectation;
- a SLSA Build level;
- source review, reproducibility, malware absence, runtime permissions, safety,
  or quality;
- current trust-root freshness or revocation state;
- a link to an A Quo persona; or
- the legal identity of a person or organization.

These are separate policy layers. A future build-expectation profile can add
exact repository, builder, build-type, and external-parameter rules without
changing what the underlying signature proves.

## Why signing is not in this slice

Keyless Sigstore signing requires an OIDC login, an ephemeral private key,
Fulcio, Rekor, and usually a CI or browser-mediated network flow. A Quo should
not quietly initiate that identity disclosure from a local verification
command. The initial signing path belongs in reviewed release CI using current
Cosign or another conforming client; A Quo can then verify the resulting
portable bundle offline. Local signing needs its own consent and disclosure
design later.

Primary references:

- [Sigstore bundle protobuf specification](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
- [Sigstore verification guidance](https://docs.sigstore.dev/cosign/verifying/verify/)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [in-toto DSSE envelope guidance](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md)
- [SLSA 1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [sigstore-rust verifier](https://github.com/sigstore/sigstore-rust)
