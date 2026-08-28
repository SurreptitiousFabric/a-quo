# Offline C2PA verification

**Status:** Linux/Omarchy verification prototype implemented; signing, trust
lists, CAWG identity validation, remote manifests, and sidecars are pending.

## What this proves

Run:

```sh
mise exec -- cargo run -p a-quo-cli -- media verify photo.jpg
mise exec -- cargo run -p a-quo-cli -- media verify photo.jpg --json
```

A `valid` result means the embedded, local C2PA manifest and its content binding
validated for the exact SHA-256 and size shown in the report. It does not mean
the signing certificate is trusted, the named creator is a verified person, the
media is true or original, or an A Quo persona signed it.

The report keeps those questions separate:

| Field | Meaning in this prototype |
| --- | --- |
| `outcome: valid` | The local embedded C2PA content binding validated. |
| `outcome: invalid` | Local C2PA evidence was read but validation failed. |
| `outcome: unavailable` | Local provenance could not be established. It may be absent, unsupported, remote-only, or unreadable. |
| `claim_signature` | Signature evidence within the manifest; not certificate trust. |
| certificate issuer/name | Bounded certificate metadata for inspection; the certificate chain and revocation state were not trusted. |
| `cawg_identity: present_unassessed` | A `cawg.identity` assertion is present; A Quo did not validate its identity claims. |
| `a_quo_persona_link` | Always `not_established` until an explicit, reviewed linking protocol exists. |

The command exits successfully only for `valid`. It still emits a structured
report before returning nonzero for `invalid` or `unavailable`.

## Isolation design

Media is hostile parser input. It never enters `a-quo-daemon`, the signing
consent protocol, a wallet, or an Omarchy plugin process.

On Linux the verifier:

1. opens the input read-only with `O_NOFOLLOW`, rejects non-regular and oversized
   inputs, and copies at most 128 MiB into a sealed memfd while calculating its
   SHA-256;
2. starts a hidden copy of the exact running A Quo executable with cleared
   environment and sends only that immutable snapshot through a pipe;
3. re-snapshots, re-hashes, and re-seals the bytes, then requires the size and
   digest to match the parent's descriptor;
4. validates the fixed `/usr/bin/bwrap` and `/usr/bin/prlimit` executables as
   regular, executable, non-symlink, non-group/world-writable system files;
5. directly replaces the launcher with Bubblewrap, using an unshared user, PID,
   network, IPC, UTS, cgroup, and mount namespace, no capabilities, disabled
   nested user namespaces, a read-only `/usr`, an isolated `/proc` and `/dev`,
   and a temporary `/tmp`;
6. exposes only a Bubblewrap-created read-only copy of the sealed input and a
   read-only bind of the already-open A Quo executable; and
7. applies a 45-second wall deadline plus 30 CPU seconds, 1 GiB address space,
   64 file descriptors, 16 processes, no core dumps, 256 KiB response output,
   and 64 KiB diagnostic output.

The worker response is a closed, versioned JSON object. Unknown fields, unknown
states, oversized output, control characters, malformed failure codes, SDK
version mismatches, and an unexpected SDK `trusted` state all fail closed.
Bubblewrap and worker diagnostics share the response channel, but the parent
parses it only after a zero exit; any extra diagnostic text makes the strict JSON
parse fail.

`--ro-bind-data` briefly creates another in-memory copy of the input. The
128 MiB first-slice limit bounds that cost. Large-video support needs a reviewed
streaming or immutable file-mount design rather than a larger unchecked limit.

## Network and dependency policy

A Quo pins `c2pa-rs` 0.90.16 with default features disabled and enables only
`file_io` and `rust_native_crypto`. The resulting graph contains the `http`
message-types crate used by SDK APIs, but no HTTP client, TLS stack, OpenSSL
backend, or `fetch_remote_manifests` feature.

The worker settings also disable remote manifest fetching, OCSP fetching,
timestamp trust, certificate trust, CAWG trust-list validation, and identity
assertion decoding. The allowed-host list is empty. The Linux network namespace
is a second, operating-system-level block. Only the copied asset exists under
`/input`, so no sidecar can be discovered from the user's original directory.

### Audited dependency exceptions

The RustSec scan currently has two repository-local, documented exceptions:

- `RUSTSEC-2023-0071` affects private-key RSA decryption in the transitive
  `rsa` crate. This worker has no RSA private key and uses the crate only to
  verify public C2PA signatures. There is no fixed upstream release. Any C2PA
  signing or other private-key RSA operation invalidates this exception.
- `RUSTSEC-2024-0370` marks transitive `proc-macro-error` as unmaintained. It is
  used while compiling the `static-iref` dependency and is not runtime code.

Both arrive only through `c2pa-rs`. The exceptions do not suppress other
advisories, and every SDK update must retry removing them. Switching to the
SDK's vendored OpenSSL backend would remove the RSA advisory but add a large
unsafe C cryptography implementation; for a verification-only isolated worker,
the narrower non-applicable Rust advisory is the reviewed tradeoff.

## Why signing is not in this slice

The [C2PA specification](https://spec.c2pa.org/specifications/specifications/2.4/index.html)
uses the claim signature for the claim-generating product. Human or organization
identity is a separate concern described by the
[CAWG identity assertion](https://spec.c2pa.org/specifications/specifications/2.4/identity/identity.html).
A Quo will not present an ordinary persona SSH key as a conforming generator
certificate or silently equate either signature with legal identity.

Later signing work therefore needs reviewed generator certificate provisioning,
certificate and revocation policy, optional CAWG signing, interoperability
fixtures, and explicit persona-link consent. Until then, A Quo can sign the
exact image file with its detached artifact proof while independently reporting
any embedded C2PA evidence.

## Remaining limitations

- Linux currently requires Bubblewrap and `prlimit` at their fixed system paths.
- Certificate chain trust, trusted timestamps, and current revocation are not
  checked.
- CAWG assertions are detected by exact label only and are not decoded or
  identity-validated.
- Remote and sidecar manifests are intentionally unavailable.
- The sandbox has no seccomp allowlist and inherits the correctness of the
  validated operating-system tools, kernel namespace implementation, and
  `c2pa-rs` parser.
- The 128 MiB cap favors images; many videos will be refused.
- Other operating systems need native isolation adapters behind the same report
  semantics.

Implementation references: the official
[`c2pa-rs` usage guide](https://github.com/contentauth/c2pa-rs/blob/main/docs/usage.md),
[`c2patool` usage documentation](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/usage.md),
and [`c2pa-rs` security policy and advisories](https://github.com/contentauth/c2pa-rs/security).
