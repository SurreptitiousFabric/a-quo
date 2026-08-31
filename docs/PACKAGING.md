# Packaging and support contract

This document defines the package boundary shared by
[#7, Package A Quo safely for Omarchy](https://github.com/SurreptitiousFabric/a-quo/issues/7)
and
[#25, Ship a portable Linux 0.x release](https://github.com/SurreptitiousFabric/a-quo/issues/25).
It is a design and acceptance contract, not evidence that a supported release
already exists. The repository contains working prototypes, a passive native
package skeleton, and a deliberately limited fakeroot/libalpm install-remove
smoke. It also contains guarded installed-core, real-pacman package-lifecycle,
and installed service/consent evaluators whose non-mutating contracts pass.
None of those armed paths has run on a marked disposable target, so there is
still no executed real package transaction, installed clean-system journey,
real service lifecycle evidence, published evaluation package, or
general-availability support promise.

The first deliverable is deliberately narrow: one repeatable walking-skeleton
journey on a pinned, clean Omarchy system. It must preserve the current busless
signing and consent boundary and make the prototype possible to evaluate without
a source checkout. A later phase qualifies the same package boundary for a
portable Linux release.

## Two phases, not a circular dependency

The two issues own different outcomes:

| Phase | Issue | Outcome | Completion does not claim |
| --- | --- | --- | --- |
| A: Omarchy package skeleton | #7 | An installable Arch package exercises one complete persona, trusted-consent, signed-plugin, install, update, and lifecycle journey on a pinned clean Omarchy image. | General Linux support, unattended updates, accessibility, production readiness, or a stable package ABI. |
| B: portable Linux release | #25 | The Phase A layout is qualified across an explicit distro/architecture/libc/package-format matrix, with published release evidence and a support/security-update policy. | macOS, Windows, external-wallet integration, plugin safety, or legal identity. |

Phase A does **not** depend on a completed portable Linux release. It creates
the reference package layout and clean-system harness that Phase B reuses.
Phase B depends on the bounded Phase A journey, then expands and qualifies it.
If another distribution cannot preserve the trusted helper path, private
runtime boundary, worker sandbox, or lifecycle behavior, it needs an explicit
adapter or remains unsupported; portability is not permission to weaken those
properties.

## “Evaluation target” and “supported” mean different things

An **evaluation target** is an environment in which the prototype is expected
to be exercised and failures reported. It has no compatibility or security-
update promise. A **supported target** has a published matrix entry, passing
clean-system evidence for the exact release, documented residual limits, and a
stated support and security-update window.

The initial Phase A target is one pinned Omarchy 4 aarch64 image with:

- glibc, a systemd user manager, procfs, and the Linux primitives used by A Quo;
- a Wayland session and a trusted compositor/display path;
- the current Omarchy plugin validator and shell rescan commands; and
- the dependencies and exact trusted paths listed below.

The image identifier, Omarchy revision or snapshot date, kernel, compositor,
package database snapshot, and test hardware or VM description must be recorded
with the evidence. “Latest Omarchy” is not a reproducible matrix entry.

This is a testability choice, not an architecture preference or support claim:
the current development and hardware-validation path is native aarch64, and
Omarchy's package infrastructure now has an explicit aarch64 build path. The
signed Omarchy release and package layer is now fixed by the unarmed profile
below. The bootstrap root filesystem, native repository snapshot, builder,
QEMU/firmware, and final clean image still have to be frozen before the
clean-system run.

### Current frozen-but-unarmed target profile

The committed
[`a-quo-omarchy4-aarch64-dec29fa-v2.profile`](../packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile)
is the current offline **expectation record**, not a retained input lock, VM
image, or evidence that a test ran. It preserves the v1 target expectations
and additionally fixes reviewed metadata needed by later input-lock work:

- the A Quo package skeleton from source commit `81658b7…`, including its
  exact filename, 12,169,663-byte size, and SHA-256;
- Omarchy stable sequence 11 and bundle sequence 15, both tied by signed
  records to source `dec29fa9…` and package source `a0e7962…`;
- the exact release-key bytes and fingerprint, signed release records,
  installers, six-package manifest, package filenames, sizes, hashes, and
  detached-signature hashes;
- the expected Ubuntu OCI index, ARM64/v8 manifest, config, one compressed-
  layer descriptor, declared DiffID, and registry-declared source metadata;
- the exact pinned Omarchy Dockerfile bytes and its 14 literal top-level APT
  request names, but no package versions or dependency closure; and
- the expected Arch Linux ARM builder-key byte identity and fingerprint under
  an unsigned exact Git commit, a source-required repository-name set, and
  explicit future database/package policy requirements.

The v2 profile has 129 closed fields and SHA-256
`3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6`.
The original
[`v1 profile`](../packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile)
remains byte-for-byte immutable at SHA-256 `84f23e93…6949da` because retained
candidate observations and their receipt name that exact historical contract.
The general offline verifier accepts only those two compiled format/ID/count/
digest combinations and defaults to the exact v2 filename. Candidate-only
bootstrap acquisition remains deliberately v1-only; accepting v2 here does
not expand its network scope or rewrite historical receipts.

The OCI digests provide content-addressed descriptor expectations, not
publisher authentication. At profile-freeze time the layer was absent from a
committed authoritative input lock, so its digest, size, and DiffID entered the
profile as descriptor declarations rather than observed authority evidence. A
later ignored candidate run, described below, provides local exact-byte
verification without changing that authority status.
The Launchpad source repository, revision, version, and creation date are
annotations on the selected registry descriptor. Serial `20260810` is derived
from the exact discovery-tag text and its matching descriptor date; it is not
a separate source attestation. None of this is source-to-image provenance.
The discovery tag has `authority=none` and is not a trust anchor. Likewise,
the pinned ALARM key hash and fingerprint express a future local policy
expectation. Its containing Git commit is unsigned; no
current publisher authorization, revocation state, trusted time, rootfs
signature verification, repository priority, effective `SigLevel`, installed
package state, database closure, package closure, or Asahi trust policy is
established.

GitHub reports the two release objects used as locators as mutable. Their tag-
specific URLs are therefore **not** trust anchors. Acquisition must check the
profile's expected hashes and verify the signed records, manifest, installers,
and packages under the exact pinned Omarchy release-key fingerprint before
parsing or executing them. Asset sizes are bounds and consistency checks, not
authentication. The lightweight Omarchy Git tag and source commit are not
signed; their authority in this profile comes only from the separately signed
release record that names the commit.

Both profiles deliberately say `state=bootstrap-unarmed` and `armable=false`.
V2 keeps the same ten unresolved inputs: retained OCI/layer bytes and a final
builder image, the Ubuntu snapshot/index/`.deb` closure, remaining builder
context and harness hash, Arch Linux ARM rootfs/signature/retained-key bytes,
an offline pacman repository lock, QEMU configuration and binaries, AAVMF
firmware, base and flattened golden qcow2 images, and exact evaluator/fixture
inputs. `mise run omarchy-evaluation-target-profile-contract` parses both
closed records offline, regression-checks the v1/v2 boundary, rejects hostile
mutations and authority escalation, and proves that `--require-runnable`
still fails for each. It downloads nothing, starts no VM, and does not
authenticate the Git commit containing either profile.

This non-actionable verifier reads the profile pathname more than once. Its
metadata checks and canonical digest detect ordinary drift but are not an
immutable-snapshot guarantee against concurrent same-inode mutation. Before
any task may construct or launch a target, it must consume one descriptor-
pinned immutable snapshot, hash and parse those same bytes, and pass an exact
race/substitution contract. The current unarmed verifier cannot authorize a
download, build, package transaction, VM launch, or evaluator run.

Expected inputs and observed build results remain physically separate. A
networked unprivileged acquisition may record candidate observations, but those
observations cannot supply their own expected hashes. A reviewed, committed
input lock must follow in a separate revision before an offline golden-image
build can arm. An already-used profile ID is never rewritten to mean a
different target. The future observation record names the externally
authenticated profile commit/path and profile digest; the profile contains no
self-hash.

The pinned A Quo archive remains unsigned, native-host-built, non-hermetic, and
`PACKAGE-SKELETON-NONPUBLISHABLE`. Its hash selects local evaluation bytes; it
does not establish a publisher, provenance, reproducibility, release status,
or safety. No rootfs, repository lock, Docker image, QEMU disk, evaluator
account, disposable marker, or runtime evidence was created by freezing this
profile.

### Candidate-only bootstrap acquisition

The repository now has a deliberately smaller network boundary for acquiring
only the inert bootstrap material that already has closed expectations. It is
not an input lock and cannot arm the target. The explicit networked task is:

```bash
mise run omarchy-bootstrap-acquire -- \
  --profile "$PWD/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile" \
  --output "$PWD/target/omarchy-evaluation-observations/new-unique-run" \
  --acknowledge-networked-candidate-only
```

The output must be a new direct child of the ignored, private
`target/omarchy-evaluation-observations/` directory. The command refuses root,
caller-supplied URLs, hashes, filenames, tools, redirect hosts, scope changes,
existing outputs, automatic retries, and automatic redirects. It copies the
canonical profile through one open descriptor, requires profile SHA-256
`84f23e93…6949da`, and runs the closed target-profile verifier before making a
request.

The acquisition scope is exactly 15 files totalling 50,718 bytes:

- the 261-byte pinned Omarchy release key; and
- release assets 01 through 07: seven data files and their seven detached
  signatures.

The unsigned 108,014-byte `omarchy-upgrade-to-quattro` asset is excluded. Its
profile digest expectation is cross-bound to the signed bundle release's
`upgrader_sha256` field, but no upgrader bytes are present to check against
that expectation. The six packages and signatures, Asahi keyring and rootfs,
OCI/APT closure, QEMU, AAVMF, and qcow2 images are also outside this task.

The release key must arrive directly from the exact raw-GitHub commit URL.
Each release asset may arrive directly or through exactly one manually checked
HTTPS redirect to `release-assets.githubusercontent.com` or
`objects.githubusercontent.com`. Curl never follows the redirect itself. The
query-bearing target is validated in memory and supplied through a private
configuration descriptor, so it is absent from argv, receipts, and diagnostic
output. Every body is bounded, then checked against the profile's exact size
and SHA-256 before publication. Server-selected filenames are never used. The
acquirer requires Curl 8.4 or newer because older releases did not enforce
`--max-filesize` for a response whose size was not declared in advance. This
limits response-body bytes; it is not a bound on headers or total wire traffic.

The offline verifier imports only the pinned key into a fresh private GnuPG
home, checks its exact primary fingerprint, and requires exactly one `NEWSIG`,
`GOODSIG`, and `VALIDSIG` under that primary key for every pair. It rejects
negative expiry, revocation, and verification statuses reported by local
GnuPG, as well as wrong signers, additional files, symlinks, changed bytes,
malformed receipts, and claim escalation. This is a point-in-time check using
the host's untrusted local clock and the retained key; it is not trusted time,
online revocation checking, or evidence of current publisher authorization.

After the signature checks, the verifier parses only three bounded, closed
ASCII/LF descriptor formats. The stable record must bind its exact sequence,
version, tag, source commit, and minimum updater version to the profile. The
bundle release must bind its sequence, tag, source commits, signed manifest,
retained updater, retained fresh installer, and profile-only upgrader
expectation. The signed manifest must bind the exact ordered six-package tuple
of sequence, name, version, architecture, archive filename, and archive
SHA-256. Extra, reordered, oversized, control-bearing, malformed, or
semantically mismatched records fail even when freshly signed by the expected
test key. A successful completed check therefore reports
`signed_descriptor_bindings=verified-non-authoritative`.

That result is deliberately narrow. The upgrader bytes are not acquired, so
only their expected digest is descriptor-bound. The package sizes, detached-
signature filenames, signature sizes, and signature hashes come from profile
policy rather than the signed manifest. No package or package-signature bytes
are present to verify, and the signed `package_source_commit` is an assertion,
not source-to-binary provenance. The check establishes no package
authorization, current key authorization, trusted time, reproducibility,
installability, script safety, or general safety. The original files remain
inert and mode `0400`; downloaded installer text is never executed. `COMPLETE`
is published only after a full receipt passes while the directory is still
marked `INCOMPLETE`.

An unsigned local receipt records the acquirer's observed bytes, signer
fingerprints, transport class, and acquisition-tool hashes. The offline
verifier recomputes the object bytes and signatures and validates the receipt's
closed form and transport allowlist, but it does not independently reenact or
authenticate the historical transport and tool observations. The receipt has
`authority=none`, no self-hash, no expected hash fields, and explicitly says
that external authentication of the profile is still required. A consumer must
supply that external expectation again and re-run:

```bash
mise run omarchy-bootstrap-candidate-verify -- \
  --profile "$PWD/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile" \
  --externally-expected-profile-sha256 84f23e93c4d240aef5c0b8e01769d9245cbdb1757eb5da7acd4a3130246949da \
  --candidate "$PWD/target/omarchy-evaluation-observations/retained-run"
```

`mise run omarchy-bootstrap-acquisition-contract` uses temporary synthetic
OpenPGP material and no network. It is part of `mise run check`; the networked
task is not. Failed runs are left private and visibly incomplete rather than
resumed or recursively deleted.

One opt-in observation on 2026-08-31 exercised this boundary on the development
host. The first fresh run stopped at the first release-asset redirect and was
retained as `INCOMPLETE`; that exposed and fixed an over-broad control-character
check. A second fresh run acquired exactly 15 objects and 50,718 bytes, observed
one direct raw-key response plus 14 one-hop `release-assets.githubusercontent.com`
responses, verified all seven detached-signature pairs, and passed a separate
offline verification. The strengthened current verifier also accepted the
three retained signed descriptor records and their exact profile/asset
bindings without promoting their authority. Its 37-line `authority=none`
receipt has SHA-256
`fc4f61d09d214f0c0594fc30d57dd246ad370e5d703c8e5263e0432741f5b491`.
Both run directories are ignored local observations, not published evidence or
trusted inputs, and this single-host result does not change the target's unarmed
status.

This boundary does not resist a compromised acquisition host or coordinated
same-UID mutation, establish current online key authorization or trusted time,
make mutable GitHub releases immutable, authenticate the A Quo package, prove
the safety of signed scripts, or provide package, rootfs, VM, clean-system,
consent, plugin, reproducibility, support, provenance, or release evidence. A
later human-reviewed commit must create a new input lock and new profile ID;
candidate observations never copy themselves into authority.

### Candidate-only Ubuntu OCI acquisition

A second, independent candidate boundary can retain the four exact OCI objects
named by the v2 profile. It does not invoke Docker or another container
runtime, construct an image, install a package, or start a VM. The explicitly
networked task is:

```bash
mise run omarchy-ubuntu-oci-acquire -- \
  --profile "$PWD/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile" \
  --output "$PWD/target/omarchy-evaluation-input-observations/new-unique-run" \
  --acknowledge-networked-candidate-only
```

Its retained registry scope is exactly 28,896,414 bytes: the 6,688-byte OCI
index, 424-byte ARM64/v8 manifest, 2,067-byte config, and 28,887,235-byte
compressed layer already pinned in the profile. The command accepts no
caller-selected URL, digest, tag, media type, platform, tool, retry, resume, or
redirect host. It obtains an anonymous Docker Registry bearer in memory. The
bearer and a query-bearing blob redirect are supplied to Curl over private
configuration descriptors rather than argv and are not written to the
candidate or receipt. Manifest responses must be direct. A blob may use one
manually validated HTTPS 307 redirect to exactly
`production.cloudflare.docker.com` or
`production.cloudfront.docker.com`, with registry authorization removed; no
hostname wildcard is accepted. Docker's current network allowlist names the
[CloudFront endpoint for image pull/push](https://docs.docker.com/desktop/setup/allow-list/),
and the OCI distribution specification requires clients not to forward
[authorization across hosts](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#api)
unless explicitly configured. Every retained response is then checked locally
against its exact size and requested SHA-256 digest.

The offline verifier requires the expected profile repository, commit, path,
and SHA-256 from its caller; the unsigned receipt cannot authenticate that
tuple for itself. For the current frozen v2 profile, invoke it as:

```bash
mise run omarchy-ubuntu-oci-candidate-verify -- \
  --profile "$PWD/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile" \
  --externally-expected-profile-repository https://github.com/SurreptitiousFabric/a-quo.git \
  --externally-expected-profile-commit e13e74dca3472e54501b35c9b57ee89f57c6aed3 \
  --externally-expected-profile-path packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile \
  --externally-expected-profile-sha256 3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6 \
  --candidate "$PWD/target/omarchy-evaluation-input-observations/retained-run"
```

Verification closes the private candidate inventory, rechecks all four byte
identities, binds the selected ARM64/v8 index descriptor to the manifest, the
manifest to the config and layer, and the config to the layer's recomputed
uncompressed DiffID. JSON inputs are bounded and must contain exactly one
top-level document. Gzip expansion is bounded to 512 MiB and 60 seconds. The
27-line receipt and verifier output keep publisher authentication,
source-to-image provenance, freshness, and safety explicitly
`not-established`; both report `authority=none`.

`mise run omarchy-ubuntu-oci-acquisition-contract` uses tiny synthetic OCI
objects and a fake Curl process, with no network. It is part of `mise run
check`; the networked acquisition task is not.

One opt-in observation on 2026-08-31 exercised this boundary on the development
host. The first fresh run stopped at the config-blob redirect because Docker
returned the current `production.cloudfront.docker.com` endpoint while the
initial closed policy named only the historical Cloudflare endpoint. It failed
before accepting any config bytes and retained an `INCOMPLETE` private run with
the exact profile, index, manifest, and an empty transfer file. After adding
only the exact Docker-listed CloudFront hostname, while preserving the 307,
digest-path, query, authorization-stripping, byte-bound, and hash checks, a
second fresh run acquired and verified all four objects and exactly 28,896,414
bytes. A separate offline invocation verified the descriptor chain and DiffID.
The completed 27-line receipt has SHA-256
`330874fa539c10a591fdd206d28f990bb4e29a8c4eca62410e31fcb44b50543e`.
Both run directories are ignored private observations rather than published
inputs or authority evidence.

Like the bootstrap candidate, this boundary detects ordinary metadata drift
but does not defeat a compromised host or a coordinated same-UID pathname
race. A later authoritative input lock and builder must consume immutable,
descriptor-pinned snapshots and must retain separate Ubuntu, Arch Linux ARM,
and Asahi trust domains. The v2 profile remains unchanged, unarmed, and still
records the final builder image and nine other inputs as unresolved.

Until Phase B evidence exists, other Omarchy snapshots, Arch Linux, x86-64,
other glibc distributions, musl, non-systemd systems, X11/headless sessions,
containers, macOS, and Windows are evaluation-only or out of scope. Portable
proof formats and Rust tests on an operating system do not make its consent,
packaging, or service integration supported.

## Phase A package and installed inventory

Phase A produces one native Arch package, conventionally named
`a-quo-VERSION-PKGREL-aarch64.pkg.tar.zst`. Splitting the package later must not
make installation without the trusted helper appear usable. A minimal install
contains exactly the following A Quo-owned runtime files:

| Installed path | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/usr/bin/a-quo` | `root:root` | `0755` | Public CLI. Its hidden re-executions are also the isolated C2PA and Sigstore workers. |
| `/usr/bin/a-quo-daemon` | `root:root` | `0755` | Private, serial, per-user signing daemon. It never runs as root. |
| `/usr/lib/a-quo/a-quo-consent` | `root:root` | `0755` | Fixed-path one-shot direct-Wayland consent process. It is not setuid and has no file capabilities. |
| `/usr/lib/systemd/user/a-quo-daemon.service` | `root:root` | `0644` | Disabled-by-default per-user lifecycle unit. |
| `/usr/lib/systemd/user-preset/90-a-quo.preset` | `root:root` | `0644` | Passive `disable` policy so an explicit global preset operation does not interpret missing policy as enablement. Installation never applies it. |
| `/usr/share/a-quo/provider-registry-v1.json` | `root:root` | `0644` | Minimal closed registry of approved analysis adapters and exact component identity. It carries no behavioural capability language; the core package initially ships an empty registry. |
| `/usr/share/doc/a-quo/README.md` | `root:root` | `0644` | Product model, commands, status, and nonclaims. |
| `/usr/share/doc/a-quo/PACKAGING.md` | `root:root` | `0644` | This package/support contract. |
| `/usr/share/doc/a-quo/SECURITY.md` | `root:root` | `0644` | Vulnerability-reporting policy. |
| `/usr/share/doc/a-quo/THREAT-MODEL.md` | `root:root` | `0644` | Shipped threat and residual-risk summary. |
| `/usr/share/licenses/a-quo/LICENSE` | `root:root` | `0644` | Apache-2.0 license text. |

The package owns `/usr/lib/a-quo`, `/usr/lib/systemd/user-preset`,
`/usr/share/a-quo`, `/usr/share/doc/a-quo`, and `/usr/share/licenses/a-quo` as
root-owned `0755` directories. Every component
from `/` through `/usr/lib/a-quo/a-quo-consent` must be a real directory or the
final regular file, root-owned, non-symlink, and not group- or world-writable.
The daemon checks this at runtime and makes consent unavailable if it is false.
Package tests must inspect the complete path, not merely the final file mode.

There are no standalone `a-quo-c2pa-worker` or `a-quo-sigstore-worker`
binaries. On Linux, `/usr/bin/a-quo` re-executes itself through `/proc/self/exe`
and passes an immutable bounded input to a no-network Bubblewrap sandbox.
Inventing separately versioned workers would create an untested mixed-version
boundary.

The package must contain no private key, signer locator, persona database,
root pin, recovery material, trusted credential, GitHub credential, live
Sigstore trust root, machine-specific Omarchy configuration, or pre-approved
publisher. Build and test fixtures must remain visibly synthetic.

### State the package does not own

The following are per-user runtime or application state, not package payload:

| Path | Expected ownership/mode | Lifecycle rule |
| --- | --- | --- |
| `$XDG_RUNTIME_DIR/a-quo/` | current user, `0700` | Exists only while the user service owns its runtime; never shared between users. |
| `$XDG_RUNTIME_DIR/a-quo/consent.sock` | current user, `0600` Unix `SOCK_SEQPACKET` | Created by the daemon; scoped cleanup must never unlink an unverified replacement path. |
| `$XDG_DATA_HOME/a-quo/personas.sqlite3` or `~/.local/share/a-quo/personas.sqlite3` | current user; parent `0700`, database `0600` | Created by the CLI, migrated by application code, backed up by the user; never created, chowned, read, migrated, or deleted by a root package script. |
| `$XDG_CONFIG_HOME/omarchy/plugins/` or `~/.config/omarchy/plugins/` | current user, as required by Omarchy | Existing Omarchy plugin state; package uninstall must not remove it. |

An explicit `--store` or custom `XDG_DATA_HOME` remains supported by the CLI.
The stock service operates on the normal environment-derived store. A custom
store requires a user-owned systemd drop-in; the package must document and test
that override before claiming it as a supported service configuration.

## Dependencies and fixed external paths

The Phase A package declares native runtime dependencies that provide:

- `/usr/bin/ssh-keygen` from OpenSSH for SSHSIG signing and verification;
- `/usr/bin/bwrap` and `/usr/bin/prlimit` for isolated C2PA and Sigstore
  verification (`prlimit` is normally supplied by `util-linux`);
- `/usr/bin/omarchy-plugin-validate` and `/usr/bin/omarchy-shell` on the
  initial Omarchy target;
- a systemd user manager and a usable `$XDG_RUNTIME_DIR`;
- the Wayland client/runtime libraries needed by the direct-Wayland consent
  process; and
- at least one root-owned, non-symlink, non-empty font of at most 4 MiB at one
  of the implementation's closed paths:
  `/usr/share/fonts/noto/NotoSans-Regular.ttf`,
  `/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf`, or
  `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf`.

For Phase A, the dependency lock chooses the first Noto path and the
clean-system test verifies it. Finding an arbitrary font through Fontconfig is
not an acceptable fallback. Every component of the selected font path must be
root-owned, non-symlink, and not group- or world-writable. The package manifest
and SBOM record the providing font package and its license.

Rust dependencies such as SQLite, tar, Zstandard, C2PA, and Sigstore parsing
are linked through the workspace build; they are not evidence that an external
daemon or network service is required. Core signing and verification are local.
Live DNS verification is the explicit exception and uses the configured
resolver. Hardware-backed signing may additionally require the user's device,
middleware, trusted askpass/PIN route, and physical interaction.

The release build uses the repository's pinned Mise configuration. The package
builder reads the Rust release from the committed `.mise.toml`, explicitly
selects that release for both its outer probe and inner Cargo build, and fails
if the observed compiler release differs. The inner build binds Cargo to the
selected `rustc` path and clears inherited compiler-wrapper settings. A package
must record the exact
`.mise.toml`, expected and observed Rust versions, `Cargo.lock`, target, build
flags, and source commit. Installing a language toolchain globally or silently
substituting the distribution Rust compiler is not the reference build.

## Busless authority and per-user service lifecycle

The package may use a systemd **user** unit to start, stop, and supervise a
process. That is lifecycle plumbing, not the approval protocol. No D-Bus method,
portal, desktop notification, Omarchy bar process, or system service may approve
a signature or receive signing authority.

The authority path remains:

```text
same-UID client
  -> private SOCK_SEQPACKET + exact file descriptor
  -> per-user a-quo-daemon
  -> fresh fixed-path a-quo-consent process
  -> direct Wayland review and explicit decision
  -> selected SSH/FIDO/agent signer
```

The daemon authenticates the peer UID, snapshots the supplied descriptor,
constructs bounded inert prompt data, launches a fresh consent process with a
cleared environment, revalidates state after consent, signs, and self-verifies
before returning a sealed proof descriptor. The consent process receives no
private key or signer locator. Neither process uses the session bus as an
approval authority.

The packaged unit is disabled by default and runs as the logged-in user. The
package also carries the passive user-preset rule
`disable a-quo-daemon.service`; neither pacman nor an A Quo scriptlet invokes
`systemctl preset`. This is a deliberate Phase-A exception to systemd's normal
preference that distributions centralize preset policy: the bounded Omarchy
package owns a fail-closed default. Phase B must coordinate or relocate the
rule into each distribution's policy rather than treating it as a universal
upstream-package convention. An administrator can still override vendor preset
policy, and a user can explicitly enable their own unit. The initial unit
contract is `ExecStart=/usr/bin/a-quo-daemon --runtime-directory=%t`,
`RuntimeDirectory=a-quo`, `RuntimeDirectoryMode=0700`, `UMask=0077`, and
`Restart=no`. The implementation may add only hardening directives shown not to
break configured signer access, Wayland, askpass/PIN handling, hardware tokens,
or the user database. The unit must:

- execute `/usr/bin/a-quo-daemon` without privilege elevation;
- use systemd's per-user runtime-directory facility to create `%t/a-quo` as
  mode `0700` and pass `%t` as the daemon runtime root;
- use a private umask and no supplementary privilege, ambient capability,
  setuid helper, or shared system socket;
- avoid `Restart=always` loops when the persona store or trusted helper is
  unavailable; and
- leave stdout/stderr limited to the daemon's existing redacted outcome log.

No `.socket` unit is shipped in Phase A. The current daemon creates and owns its
`SOCK_SEQPACKET` listener and cannot accept a systemd-inherited descriptor.
Systemd-scoped runtime-directory removal supplies bounded cleanup after the unit
has fully stopped, including abrupt death; it must be tested against ordinary
stop, `SIGKILL`, restart, and replacement-path attacks. If that behavior cannot
be demonstrated on the target user manager, the package must retain the
current fail-closed stale-path behavior and document an exact operator check;
it must not add an unconditional `rm` pre-start command.

The user first creates a persona store, then explicitly runs
`systemctl --user enable --now a-quo-daemon.service`. Starting without a store
fails visibly and grants no authority. Enabling lingering is neither required
nor recommended: there is no reason for a desktop consent service to outlive
the user's login session. Administrative installation must not globally enable
the unit for existing or future users.

Applying the global `disable` preset later may remove a global enablement link,
so install and upgrade scripts must not apply it unconditionally. It does not
remove an individual user's enablement under that user's configuration.

## One complete Omarchy walking-skeleton journey

Phase A is not accepted because the three binaries launch. The following whole
journey must pass on a clean pinned Omarchy image using the installed package,
not `cargo run` or files from the build tree.

1. **Verify and install the A Quo package.** The test records the package digest,
   verifies its release evidence, installs it through pacman, compares the
   installed file list with the inventory above, and checks every owner, mode,
   dependency, unit state, trusted-helper path component, and selected font.
   No user database or plugin is created and the user service remains disabled.
2. **Create a test publisher persona.** As an ordinary desktop user, generate a
   disposable OpenSSH test key outside the repository. Run `a-quo persona
   create --label ... --purpose project`, `persona key-add`, and `persona
   key-bind`. Record only the public synthetic fixture material. Confirm the
   database and parent permissions.
3. **Start the packaged user service.** Enable and start
   `a-quo-daemon.service`. Confirm one daemon for that UID, no root daemon, the
   `0700` runtime directory, the `0600` socket, and fail-closed behavior for a
   different UID. Confirm that no D-Bus or portal call can approve a request.
4. **Build and sign plugin version 1.** The test harness creates a deterministic,
   harmless `.tar.zst` fixture satisfying [the Omarchy archive
   contract](OMARCHY.md). Run `a-quo request-sign PLUGIN.tar.zst --persona-id
   ID --kind software`; review and approve the exact digest in the packaged
   consent window. Verify the returned proof against the exact archive. A
   declined or altered request must produce no usable proof.
5. **Inspect and install version 1.** Run `a-quo omarchy inspect` and retain its
   separate exact-byte, signature, local-publisher, archive, executable-file,
   Omarchy-validation, and `runtime safety: not_evaluated` results. Then run
   `a-quo omarchy install ... --yes` with
   `--accept-behavioral-analysis-not-run`. Confirm that the second flag is
   required independently because no reviewer ran, then confirm official
   validation and rescan, the A Quo receipt, normalized extracted permissions,
   and that A Quo made no enable call. Record the exact pre- and post-operation
   configuration observations rather than claiming the plugin was never
   transiently loaded. Enablement remains a separate Omarchy/user action.
6. **Sign and update to version 2.** Create a strictly newer deterministic
   fixture under the same plugin ID and persona, sign it through the daemon,
   inspect it, and run `a-quo omarchy update ... --yes` with
   `--accept-behavioral-analysis-not-run`. Confirm exact publisher continuity,
   atomic exchange, unchanged configuration bytes in the uncontended case,
   exact pre/post reference observations, receipt update, and successful
   rescan. Injected rescan failure must exchange the old directory
   back; a rollback failure must report manual attention rather than success.
   The matrix exercises this once while unreferenced and once after an explicit,
   separately recorded Omarchy enable decision; A Quo never performs that
   decision itself. A never-transiently-loaded claim requires Omarchy
   cooperation through a coordinated transaction or inhibit interface and is
   not part of the current prototype.
7. **Exercise rejection.** Prove rejection of altered archive bytes, altered
   proof, unrecognized/retired/compromised/terminally revoked/evidence-only
   publisher state as applicable, label disagreement, plugin-ID change, equal
   version, downgrade, unsafe archive paths/types, oversized input, an existing
   unmanaged or Git plugin, and a candidate containing `.a-quo-install.json`.
8. **Exercise service and package lifecycle.** Stop and restart cleanly; kill
   the daemon and prove bounded stale recovery or the documented fail-closed
   procedure; perform the supported package upgrade; test interruption at the
   package transaction's defined kill points; uninstall; and verify the result
   described below. Repeat from a fresh snapshot to prove the harness is not
   relying on developer-machine state.

Using one local synthetic publisher proves the packaged path works; it does not
prove real publisher onboarding, independent root distribution, publisher
trust, plugin safety, or compatibility with a real plugin corpus. Those are
separate #3, #8, and #10 evidence.

## Install, upgrade, downgrade, interruption, and removal

### Install

The package transaction installs only root-owned payload files and dependency
metadata. Pre/post-install actions may refresh the package manager's normal
caches and print user instructions. They must not enumerate logged-in users,
start or enable user services, initialize a persona, modify Omarchy settings,
touch a signer, or contact a network service.

Installing the preset file is passive: the transaction does not run a preset
operation. Clean-system evidence must separately show that installation creates
no enablement link and that an explicit offline global preset leaves the unit
disabled.

A missing or unsafe consent helper or font leaves verification commands usable
where their own dependencies exist, but trusted signing requests fail closed.
The package and status output must not describe such an install as fully
operational.

### Upgrade

An upgrade must preserve all per-user databases, proof files, root pins,
signer bindings, receipts, and plugins. Database migration remains an
application transaction under the owning UID; the root package script never
opens the database. The Phase A supported procedure stops the test user's
daemon, replaces package files transactionally, and starts it again only after
the package verifies. A failed replacement leaves either the prior complete
package or an explicitly diagnosed non-operational state, never an apparently
approved mixed installation.

The IPC is versioned, but the current protocol does not identify a complete
application build across an otherwise compatible version. Before live upgrade
is supported, tests must cover every old/new CLI-daemon-helper pairing or add a
fail-closed build/protocol compatibility check. Merely replacing files beneath
an already running daemon is not a completed upgrade.

### Downgrade

A Quo application-package downgrade and Omarchy plugin downgrade are separate
events. The plugin updater already rejects equal or lower semantic versions.
The Phase A package workflow must also refuse an older A Quo package before
mutation and explain how an administrator enters an explicit, documented
recovery procedure if a rollback is necessary. Pacman's ability to install a
local older archive is not itself a safe rollback design. The chosen libalpm
hook, installer preflight, or equivalent mechanism must be proven on the clean
target; a post-transaction warning does not satisfy this gate.

Development package versions now include the complete reachable Git commit
count before the abbreviated commit ID. When the project version and package
release do not regress, this makes a descendant sort after its ancestor under
pacman's version comparison and rejects shallow-history builds. The project
version still needs a monotonic release policy. This mechanism does not by
itself implement the required downgrade authorization or freshness policy,
especially for unrelated or rewritten histories.

A supported A Quo rollback requires a compatible data schema, an exact retained
package and release evidence, a stopped user daemon, a backup and restore plan,
and a post-rollback verification. Until that exists, downgrade is refused and
unsupported rather than silently attempted.

### Interrupted transaction and stale recovery

Tests interrupt before payload replacement, during the package transaction,
after payload replacement but before lifecycle instructions, during ordinary
daemon stop, and through abrupt daemon death. At every point:

- an incomplete trusted helper is never accepted by the path validator;
- no service runs as root or against another user's store;
- no proof is released without completed consent and self-verification;
- package repair can converge to one complete version without deleting user
  state; and
- the runtime socket is either safely recreated after scoped cleanup or remains
  fail-closed with an exact, non-destructive recovery instruction.

The recovery instruction must first establish that no live daemon owns the
exact socket. It may remove only the current user's exact
`$XDG_RUNTIME_DIR/a-quo/consent.sock` or stop the owning user unit so its
manager removes the scoped runtime directory. No recursive cleanup of an
unresolved path and no root-wide search/removal is allowed.

### Uninstall

Uninstall stops and disables only the requesting user's unit when that user
chooses to do so; a root package removal does not impersonate or enumerate
users. It removes package-owned binaries, unit, documentation, and license
files. It must not remove user databases, public evidence, root pins, keys,
plugins, Omarchy enablement, install receipts, or unrelated runtime entries.

After removal, an already running daemon must not be represented as supported.
The documented user procedure stops it before removal; the clean-system test
also checks the hostile case and proves it cannot launch a now-missing helper
or release a newly requested proof. Reinstall must discover the retained store
under its owning user, perform any application migration normally, and require
the user to enable/start the service again.

“Purge my A Quo identity data” is a distinct, destructive user operation and is
not implemented by package uninstall. Any future purge command must enumerate
exact targets, preserve portable public evidence on request, never delete
private keys it does not own, and require separate explicit consent.

## Administrative and user actions

Root or package-administrator authority is limited to:

- verifying, installing, upgrading, repairing, or removing the native package;
- supplying system dependencies and the root-owned trusted helper/font paths;
- inspecting package ownership, modes, checksums, and unit files; and
- applying an explicitly documented package rollback or security update.

The desktop user, not the administrator or package script, creates personas,
binds signer locators, enables/stops the user service, approves signatures,
manages root pins and backups, inspects/installs plugins, and decides whether to
enable a plugin in Omarchy. No administrative action may manufacture consent,
pre-enrol a publisher, import a legal identity, or read a private signer.

## Clean-system qualification matrix

Every release candidate records an exact result and evidence link for each
applicable cell. A blank, skipped, developer-machine-only, or “should work” cell
is a gap.

| Evidence class | Phase A pinned Omarchy 4 aarch64 | Phase B each claimed target |
| --- | --- | --- |
| Clean install and inventory | Required | Required |
| Full walking-skeleton success | Required on real Wayland session | Required, or target explicitly excludes trusted signing and is named as verifier-only |
| Exact owner/mode/path tamper | Required | Required |
| Cross-UID and same-UID protocol abuse | Required | Required |
| Hostile plugin/package input | Required | Required |
| Consent decline/cancel/timeout/focus loss | Required | Required for trusted-signing targets |
| Missing/unsafe helper, font, signer, Omarchy command, Bubblewrap, `prlimit`, procfs | Required | Required when applicable |
| Upgrade and old/new process combinations | Required for the supported Phase A procedure | Required |
| Application and plugin downgrade refusal | Required | Required |
| Package interruption/repair | Required | Required |
| Plugin exchange/rescan rollback | Required | Required on Omarchy targets |
| Daemon crash, stale socket, restart, logout/login | Required | Required for daemon targets |
| Uninstall/reinstall with retained user state | Required | Required |
| Keyboard path, scaling, contrast, and real assistive technology | Record current exclusions; blocks general availability | Required to the claimed accessibility scope |
| Real Omarchy plugin corpus | Separate #10 gate; not required for the synthetic skeleton | Required before broad Omarchy compatibility claims |
| Reproducibility across independent builders | Record current result | Required only if claimed; otherwise label builds non-reproducible |

The test image begins without A Quo build artifacts, developer checkout paths,
Mise caches, user services, persona state, or synthetic publisher state. The
result records whether tests are VM, bare metal, or simulated. Security-critical
Wayland, FIDO/agent, power-loss, and assistive-technology claims require real
environment evidence where simulation would change the boundary.

## Release artifact and evidence contract

### Current non-publishing scaffold

The repository has a bounded `mise run release-scaffold` development task. It
builds the current three Linux executables with the locked Rust graph, stages
them under an uninstalled `/usr`-shaped tree, emits one CycloneDX 1.5 Rust-crate
dependency graph for each shipped binary, records deterministic source/build
metadata, and verifies a sorted `SHA256SUMS`. It refuses a dirty source tree by
default; `A_QUO_RELEASE_ALLOW_DIRTY=1` exists only to exercise the scaffold
during development. Such output is named `DIRTY-NONPUBLISHABLE`, and its
metadata records `source_dirty=true`.

The separate `mise run arch-package-skeleton` task runs only from a clean Git
tree on native AArch64. It creates an exact-commit source archive, reads its
version and Arch recipe from the same immutable Git object with replacement
refs disabled, rejects inherited Git repository/index redirection and shallow
history, and derives an ancestry-ordered revision from the complete reachable
commit count. It explicitly
pins the committed Rust release, and builds with network access disabled for
both Mise and Cargo. It executes the verifier stored in that commit, compares
packaged assets with committed blobs rather than live worktree files, and
refuses to publish its local output if HEAD or worktree cleanliness changes
during the build. The verifier checks the exact payload,
absence of hooks/socket units and unexpected entry types, every entry's root
ownership and mode, the closed dependency and ELF-library sets,
AArch64/glibc executable shape, disabled service definition, exact passive
disable preset, and exact empty provider registry. The package is not installed
or enabled by the task.

After building an exact clean-HEAD package, the opt-in
`mise run arch-package-lifecycle-smoke -- PACKAGE COMMIT` task can apply that
archive to a disposable alternate libalpm root under fakeroot and remove it
again. It rejects Git repository/object overrides, copies the caller's package
once into a private snapshot, and then uses only that snapshot for verification,
installation, extraction, probes, and the final digest check. It runs the
verifier stored in the named commit and isolates every
package database, cache, keyring, hook, log, home, and temporary path, disables
package scriptlets, has no configured repositories, accepts the explicitly
unsigned local skeleton only after the committed static verifier succeeds, and
bypasses dependency resolution explicitly. It checks the exact installed inventory, simulated
root ownership and modes, pacman's mtree result, the passive service/preset
state, and preservation of seeded persona and plugin state. Its bounded binary
execution probes (`--version` and consent fail-closed) run inside a no-network
Bubblewrap namespace with the host `/usr` runtime and installed payload mounted
read-only.

This smoke is useful evidence about libalpm application and removal, but it is
not a chroot, container, clean Omarchy image, live systemd user manager, real
root-ownership test, dependency-resolution test, upgrade test, Wayland consent
test, or Omarchy integration test. Its output records each of those exclusions.
The package metadata therefore continues to say
`package_install_test=not_performed`; clean-system evidence remains a separate
release gate.

A separate opt-in transition task accepts two package files, caller-pinned
SHA-256 values for those files, and two named source commits:

```text
mise run arch-package-upgrade-smoke -- \
  OLD_PACKAGE OLD_SHA256 OLD_SOURCE_COMMIT \
  NEW_PACKAGE NEW_SHA256 NEW_SOURCE_COMMIT
```

It requires a clean, non-shallow, ungrafted repository with both named commit
objects locally available and reachable from current `HEAD`; the old commit
must be an ancestor of the new one, and the exact package versions must sort in
that direction. Before creating any package-manager state, it copies both
inputs through bounded no-follow readers,
requires the private copies to match the caller's digests, checks their
structure, versions, and committed non-binary assets with a private snapshot of
the verifier committed at current `HEAD`, and rechecks the source and snapshots.
The commit association is a compatibility/policy check, not source-to-binary
provenance for the three executables. The task then uses only an isolated
fakeroot/libalpm root to install the old package, upgrade to the new package,
remove it, and reinstall the new package. At each installed stage it checks the
exact version, closed inventory, file bytes, simulated ownership and modes,
empty optional-reviewer registry, disabled service state, and the contents,
type, inode, owner, mode, link count, and size of two seeded persona/plugin
sentinel files.

`mise run arch-package-upgrade-contract` exercises this harness with synthetic
commands and hostile seam cases without touching host package state. The
transition smoke disables Git lazy fetching before inspecting the named source
objects and performs no repository sync, signature verification,
dependency resolution, scriptlet or hook execution, real-root installation,
live service operation, downgrade attempt, interruption recovery, Omarchy
integration, or behavioural analysis. It also does not establish resistance to
same-UID pathname substitution or archive decompression/resource exhaustion:
its private files are repeatedly path-opened by Bash, the verifier, libalpm,
and `bsdtar`, and the existing skeleton verifier has no complete uncompressed
archive resource limit. Removal followed by reinstall is not a rollback test.
It is bounded evidence about caller-pinned bytes in an isolated libalpm
transition, not clean-system, provenance, or release evidence.

The resulting directory is explicitly marked
`PACKAGE-SKELETON-NONPUBLISHABLE`. It is a native package-format and payload
prototype, not the accepted Phase A package: the build is not hermetic, its
native dependency versions are not frozen into a clean image, and it has no
complete native-package SBOM, provenance attestation, signature, independent
reproducibility comparison, real-system install/upgrade/uninstall evidence, or
publication. The simulated install-remove and two-version transition smokes
above do not satisfy those real-system lifecycle gates.

### Current installed-core evaluator

`mise run installed-omarchy-core-lifecycle-contract` checks the evaluator's
syntax, ShellCheck result, fail-first acknowledgement gate, required evidence
fields, and absence of build-tree, D-Bus, configuration-write, or Omarchy
enable/disable paths. This task is non-mutating and runs as part of the release
scaffold lint.

The separate `mise run installed-omarchy-core-lifecycle` task is intentionally
armed and one-shot. Before its first temporary-directory creation, it requires:

- an exact acknowledgement string;
- root execution and an exact root-owned mode-`0400` disposable-evaluator
  marker;
- the fixed `a-quo-evaluator` account and home, safe existing Omarchy
  directories, an absent evaluator persona state and plugin target;
- an exact pinned Omarchy package query, evaluator-owned Wayland socket, and
  installed root-owned `/usr/bin/a-quo` owned by the `a-quo` package;
- the exact empty root-owned provider registry; and
- two distinct canonical package inputs with caller-pinned SHA-256 values.

Using installed binaries only, the evaluator creates a disposable self-asserted
publisher, directly signs and verifies two exact package versions, inspects
them, proves both missing CLI acknowledgements fail before store or plugin I/O,
and records a privacy-limited point-in-time reference observation. It then
installs version 1, updates to version 2 under the same persona, refuses the
downgrade, and moves the managed plugin into uninstall recovery quarantine. It
independently checks the returned retained namespaces, package bytes, manifests,
and receipts. It emits sanitized JSON only after unbinding and removing the
disposable signing key and its temporary work tree. The persona store and A Quo
lifecycle recovery directories remain deliberately available for inspection,
so the same evaluator state cannot be silently reused.

This is an evaluator scaffold, not completed evidence. It was not run on this
development machine and does not establish a clean image, package installation,
service/helper lifecycle, trusted Wayland consent, behavioural analysis, plugin
safety, runtime load state, or an Omarchy enable action. Running it on a marked
system covers only the installed core portion of steps 2, 5, 6, and the plugin
downgrade/removal parts of steps 7 and 8 above. The complete clean-system
walking skeleton and failure matrix remain required.
No Plug & Prejudice adapter is bundled; the base registry is empty and core
identity/signing remains usable without behavioural review.

### Guarded real-pacman package lifecycle bridge

`mise run installed-a-quo-package-lifecycle-contract` checks the bridge's
syntax, ShellCheck result, exact fail-first acknowledgement, pre-mutation
target and input gates, four-transaction ordering, installed-state checks,
failure behavior, cleanup ordering, and evidence nonclaims in the current
source. Before its only bridge invocation, it makes a private byte snapshot,
checks syntax, and requires the exact closed 19-line acknowledgement prefix;
the snapshot is then invoked only with the acknowledgement absent. Eight
security-critical function sections have exact source hashes. A fourteen-case
source-mutation matrix must reject an unsafe pre-acknowledgement side effect,
four early-success gate/verification bypasses, removed transition gates, a
Pacman dependency bypass, service mutation, automatic package reversal, a
false signature claim, lock creation, Pacman-hash bypass,
package-database-check bypass, and executing-bridge hash bypass. The contract
also rejects the currently modelled dependency, signature-policy, scriptlet,
repository, behavioural-scanner, direct generic D-Bus, and
session-bus-environment bypass spellings. It is non-mutating with respect to
package and evaluator state and runs in the normal check graph. Passing it is
source-shape regression evidence, not exhaustive control-flow, hook, binary,
or runtime proof. It does **not** prove that Pacman ran.

The separate `mise run installed-a-quo-package-lifecycle` task is destructive,
root-only, one-shot, and restricted to a native AArch64 Arch-family machine. It
requires all of the following before persistent package or evaluator state is
created:

- the exact root-owned mode-`0400` disposable-target marker, fixed
  `a-quo-evaluator` account/home, evaluator-owned Wayland socket, and exact
  installed `omarchy` or `omarchy-dev` package query;
- an initially and specifically absent A Quo package with a consistent local
  package database; absent payload and `.pacsave` leaves, daemon,
  evaluator-scoped and global enablement, evaluator user-manager unit, persona,
  plugin target, and one-shot evidence root. Other users' runtime enablement is
  not inspected;
- two different, canonical, root-owned A Quo package files with no group/world
  write bits. Each must be no larger than 256 MiB and bound to a
  caller-supplied SHA-256, exact package query, and ordered full source commit;
- two exact caller-hash-pinned plugin fixture packages and already satisfied
  local dependencies;
- a clean, complete, standalone, non-shallow, ungrafted, unreplaced,
  non-partial Git checkout. Its bounded Git metadata and all tracked paths must
  be root-owned with no group/world write bits, and it may use no alternate
  object store. The executing bridge must resolve to its exact repository path,
  be the tracked mode-`100755` blob at `HEAD`, and match that blob's SHA-256 and
  a stable before/after file identity; those facts are rechecked before every
  transaction. Root remains able to change these inputs;
- stable root-owned Pacman configuration and include files, a bounded inventory
  of effective hooks and repositories, an exact Pacman owning-package query,
  integrity result, metadata identity, and binary SHA-256, no existing Pacman
  database lock, a pre-provisioned root-owned mode-`0700` bridge-lock directory
  and singly linked mode-`0600` lock file, and a working fresh network
  namespace.

The intended sequence is exact: copy both package files into bounded private
snapshots; run the verifier committed at the current policy revision; install
the old package using real host `pacman -U`; verify its exact query, Pacman
integrity and registered inventory, installed bytes, root ownership and modes,
dependencies, empty reviewer registry, and disabled/inactive service; upgrade
to the newer package and repeat those checks; run the committed installed-core
evaluator against that newer package; remove A Quo using real host `pacman -R`
and prove every package leaf is absent while the evaluator's user evidence is
byte-for-byte retained; then reinstall the same newer package and prove the
retained state is unchanged. Private temporary work is identity-checked and
removed before success JSON is emitted. Retained-state count and byte limits
are applied after enumeration, but discovery and archive extraction are not
resource-contained.

Every direct Pacman transaction process tree, including target hooks, and the
nested core-evaluator process tree receives a fresh network namespace. This
does not close inherited descriptors or filesystem Unix sockets, prevent a hook
from delegating host work through a system service, or establish whole-machine
network silence. The target's real hook policy remains active and its
configuration and inventory are pinned between stages, but the bridge does not
independently enumerate which hooks actually triggered. Read-only `systemctl`
checks sample the evaluator's active/enabled state and global enablement at
boundaries; they do not prove the unit was never transiently started or enabled
and do not inspect other users' runtime enablement. No A Quo signing or consent
authority is delegated through D-Bus. Arbitrary target-hook IPC is not thereby
constrained or audited.

The acknowledged destructive path has **never been run**, so no real
package-transaction evidence exists yet. Normal checks have executed only its
fail-first missing-acknowledgement path. A successful run deliberately leaves
the newer A Quo package installed and retains the evaluator persona, plugin,
and evidence state for inspection. A failure after mutation performs no
automatic package reversal; it may leave the old package, new package, no
package, or partial/indeterminate package, hook, or service state, and it
retains private diagnostic material. It is therefore suitable only for a
disposable target prepared for this exact purpose.

Even a future successful run would not establish an A Quo package downgrade
attempt or refusal, interruption or power-loss recovery, rollback,
unrelated-Pacman-process exclusion, package signatures, independent source
authentication, source-to-binary provenance, complete Pacman runtime-library
identity, archive resource containment,
repository sync or dependency installation, a live service or consent flow,
behavioural review, plugin safety, a clean-system result, publication, or
release readiness. It also does not exclude same-UID mutation during retained
state traversal. The nested plugin downgrade check is not a package downgrade
check, and removal followed by reinstall is not rollback.

### Current installed service/consent evaluator

The repository also contains
`mise run installed-a-quo-consent-lifecycle-contract`. Its local non-mutating
contract check passes: it checks shell syntax and ShellCheck, confirms that the
exact acknowledgement/root/marker gates precede temporary state, and rejects
build-tree execution, approval automation, input injection, bus authority,
user-manager environment mutation, recursive deletion, and trusted-helper
mutation in the harness. Passing this contract says what the script is allowed
to attempt; it is not evidence that its interactive path succeeded.

The separate `mise run installed-a-quo-consent-lifecycle` task is armed,
one-shot, and interactive. Before mutation it requires the same exact
root-owned disposable marker and `a-quo-evaluator` account, caller-pinned A Quo
and Omarchy package queries, a pre-existing evaluator-owned Wayland/user-manager
context, an exact caller-pinned signing artifact, the stock package-owned unit
and three installed binaries, the root-owned empty provider registry, the
trusted packaged font, an initially disabled/inactive service, and absent A Quo
runtime and persona state. It neither imports environment into the user manager
nor adds a service drop-in.

If eventually executed, the evaluator is designed to record missing-store
failure without a socket, explicit per-user enablement, one installed daemon,
private runtime/socket metadata, denial of an unprivileged `nobody` `stat`
probe against the runtime and socket paths, the fixed helper as the daemon's
direct child with a closed environment, one
operator-observed manual decline with no proof, one operator-observed manual
approval followed by exact-byte verification and altered-byte rejection,
ordinary stop/restart, forced daemon death and runtime cleanup, and restoration
to disabled/inactive state. The harness contains no input-injection or
auto-approval path, but input origin is not machine-verifiable. It uses only a
disposable OpenSSH file key, then unbinds it and removes its bounded temporary
state before emitting sanitized evidence.

The armed path has **not** been run. Therefore none of those intended checks is
runtime evidence yet. The scaffold does not establish a clean system, package
installation or transaction behavior, accessibility, secure attention against
same-session overlays, SSH-agent/FIDO/PIN behavior, peer-credential rejection
beyond filesystem denial, Omarchy plugin lifecycle, behavioural analysis,
plugin safety, or release readiness. It covers only a future installed
service/helper and manual decline/approval slice of steps 3 and 4; it neither
completes the walking skeleton nor changes any issue's maturity.

The three-binary release scaffold remains deliberately narrower. It does not
include the service unit, empty provider registry, documentation, license,
native-package dependency inventory, selected font/package inventory, package
metadata, provenance, signature, independent reproducibility comparison,
installation, or publication. Its metadata records those omissions.
`cargo-cyclonedx` also preserves several
third-party crates' deprecated slash-form license declarations as named
licenses and emits warnings; a release requires an explicit license/SBOM review
rather than suppressing or interpreting those warnings as success.

Every published Phase A evaluation candidate and every Phase B release is an
immutable set whose members refer to the exact package SHA-256:

- the native package `a-quo-VERSION-PKGREL-ARCH.pkg.tar.zst`;
- `SHA256SUMS`, covering every downloadable artifact;
- an SPDX JSON or CycloneDX JSON SBOM covering Rust crates, toolchain, native
  dependencies, packaged documents, and the selected font package/license;
- an in-toto provenance statement naming the source commit, locked Mise
  toolchain, builder identity, command/task, target, inputs, and package digest;
- a Sigstore v0.3 bundle authenticating the package/provenance publication once
  #12 supplies the release identity and publication policy; and
- release notes naming the evaluation/support matrix, migrations, known
  limitations, nonclaims, security-update window, and verification procedure.

Checksums detect accidental or unauthenticated mismatch only when obtained
through a separately authenticated channel. A Sigstore bundle is useful only
with the exact expected certificate identity, issuer, trusted-root snapshot,
transparency/time policy, and offline verification instructions. A Quo's own
prototype verifier requires those values explicitly; the release must not tell
users that “Sigstore verified” is a universal trust decision.

The SBOM is an inventory, not evidence of no vulnerabilities. Provenance says
which declared process produced bytes, not that the source or builder was safe.
A successful build is not reproducible-build evidence; #11 must compare
independent outputs before that claim is made. TUF freshness, threshold roles,
delegation, and rollback protection remain #15 and are not implied by a newer
version number or a signed checksum.

Before #12 is complete, Phase A artifacts may be attached as explicitly
labelled evaluation artifacts with checksums, SBOM, and unsigned or CI-signed
provenance evidence. They must not be called a supported release, and the
absence of the final publisher policy must be visible in the verification
instructions.

## Prototype acceptance and phase handoff

Issue #7 may leave Implementing for **Prototype complete** only when an exact
public revision and immutable clean-system evidence demonstrate:

- the complete inventory, dependency, owner/mode, service, and busless-boundary
  contract above;
- the full synthetic Omarchy walking skeleton through installed binaries;
- success, tamper, hostile-input, and failure-path tests, including package
  upgrade, downgrade refusal, interruption, uninstall, and stale recovery;
- documentation of every administrator action and every remaining manual user
  action; and
- an evaluation artifact set with verification instructions and explicit
  residual limitations.

Prototype complete still means a bounded prototype. #7 cannot reach Done
without the applicable hardening, clean-system, accessibility-scope, and
independent-review gates in [MATURITY.md](MATURITY.md). #8, #9, #10, #12, #14,
and #15 are not silently absorbed into #7; their missing outcomes remain
separate and visible.

The Phase A handoff to #25 is the exact package layout, build recipe, test
harness, artifact schema, and evidence record. #25 then freezes a supported
matrix and, for each claimed target:

1. maps equivalent package paths and dependencies without weakening the trusted
   boundary;
2. repeats lifecycle, hostile-input, consent, sandbox, and clean-system tests;
3. publishes the complete authenticated artifact set;
4. states install, verification, troubleshooting, migration, rollback,
   security-update, end-of-support, and vulnerability-response policies; and
5. distinguishes full trusted-signing support from verifier-only packaging.

If #25 changes the helper path, service protocol, worker sandbox, data schema,
or consent authority, that target returns to Design rather than inheriting #7's
evidence.

## Nonclaims and current uncertainties

Even a package that passes Phase A does not establish that:

- A Quo is production-ready, independently audited, generally accessible, or
  safe for high-risk or unattended use;
- a signature makes an artifact or Omarchy plugin safe, reviewed, truthful,
  original, current, or malware-free;
- a self-created persona is a legal or government identity;
- the ordinary Wayland consent window is a secure-attention surface or resists
  hostile same-session overlays;
- same-UID malware cannot alter local persona, receipt, plugin, or Omarchy
  configuration state;
- Sigstore, SBOM, provenance, semantic versioning, or a package-manager
  transaction supplies TUF-style freshness or rollback protection; or
- passing on one pinned Omarchy image supports Arch generally, another Linux
  distribution, another architecture/libc, macOS, or Windows.

The implementation phase must resolve and record, rather than hide, these
remaining choices:

- the exact retained bootstrap/rootfs, native dependency lock, VM tooling, and
  flattened golden image for the unarmed Omarchy profile;
- the systemd user-manager behavior for `%t/a-quo` cleanup after every tested
  stop/crash sequence;
- the package-manager mechanism that refuses an A Quo downgrade before
  mutation and its explicit recovery escape hatch;
- the compatibility rule for a running old daemon with newly installed CLI and
  consent binaries;
- whether Phase A release evidence is CI-signed evaluation evidence or waits
  for the final #12 publisher identity; and
- the support window and security-update response promise that #25 can
  realistically maintain.

Until those items have tested answers, the package archive remains a local
non-publishable skeleton; it is not an installable evaluation candidate or a
supported product.
