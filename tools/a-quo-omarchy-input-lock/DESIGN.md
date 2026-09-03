# Exact-input lock verifier structure

This crate verifies already-frozen input selections and narrowly bounded
prerequisites. The shared code is
limited to data and byte-processing rules that are identical for those
classes; it does not define a generic verifier, policy hierarchy, provider, or
authority surface.

| Shared mechanism | Exact scope |
| --- | --- |
| Lock record model | Common lock/profile identity, authority boundary, target binding, and exact object records |
| Report model | Ordered `key=value` serialization, common identity/object prefix, and closed verification/nonclaim/activity states |
| Descriptor snapshots | The existing bounded, sealed, exact-directory path used by OCI, AAVMF, and QEMU |
| Debian archive helpers | Strict three-member ar parsing, bounded zstd decompression, canonical tar paths, and byte-slice SHA-256 used identically by AAVMF and QEMU |

The class modules keep their semantic policy:

- `lib.rs` (OCI): descriptor-chain JSON policy, layer and diff-ID checks;
- `alarm_rootfs.rs`: the 1 GiB local snapshot boundary, OpenPGP key and
  signature checks, and rootfs-specific policy;
- `aavmf.rs`: Debian package identity and exact firmware-member policy;
- `qemu.rs`: Debian package set, ELF policy, and exact machine script.
- `apt.rs`: the non-authoritative class-02 candidate lock/profile policy;
- `gpgv_runtime.rs`: issue #65's exact OCI `gpgv` runtime closure and bounded
  static ELF policy; it contains no runtime executor or signature replay.
- `gpgv_isolation.rs` (Linux only): issue #65's fixed, non-executing namespace,
  noexec-tmpfs materialization, self-probe, and verified-cleanup boundary. It
  can execute only the current A Quo verifier's hidden probe mode; the retained
  loader, `gpgv`, keyring, and signed inputs are never execution inputs here.

ALARM's snapshot implementation is deliberately not merged with the smaller
`a_quo_ipc::SealedArtifact` path: its reviewed rootfs limit and GPG descriptor
flow are materially different. AAVMF and QEMU share Debian mechanics but keep
separate package/member policies. The x86_64 profiles and locks, builder and
joined-lifecycle tools, execution, acquisition, and build
authorization are outside this refactor.

The committed lock files and byte-exact inspection report fixtures are the
compatibility boundary. Refactoring must not rename profiles or evidence
namespaces, reorder report fields, remove a nonclaim, or turn a selected input
into provenance, publisher authentication, freshness, safety, or authority.
