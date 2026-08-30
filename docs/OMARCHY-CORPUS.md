# Pinned Omarchy plugin corpus

Status: **source baseline and hostile-fixture design; package/proof corpus and
clean-system results not yet frozen**

This document defines the initial revision-pinned corpus for A Quo Omarchy
package, structural inspection, native-report binding, update, and lifecycle
testing. It fixes the source revisions that can be verified today, records what
is still absent, and sets rules for constructing hostile variants without
implying that a signature or test fixture endorses unsafe code.

This is not Plug & Prejudice's behavioural-analysis corpus. Plug & Prejudice
owns expected command/resource discovery, facts, inferences, unknowns,
coverage, limitations, scanner errors, obfuscation handling, and
false-positive/false-negative results. A Quo owns immutable packages and
proofs, safe archive structure, exact scanner-report subject binding, local
policy, consent, and install/update lifecycle expectations.

The corpus supports issues #7–#10. It is not evidence that those issues are
complete. In particular, no canonical package bytes, A Quo proof bundles, or
clean-system install results are frozen here yet.

## Frozen source baseline

All revisions below were checked both in the local clone and at the public
GitHub commit URL. Only committed trees are in scope.

| Corpus subject | Frozen revision | Manifest identity and version | Intended role |
| --- | --- | --- | --- |
| [omarchy-cointoss](https://github.com/alkevintan/omarchy-cointoss) | [`5e4dd9093154a16aab65f7e25656c6eb621055d0`](https://github.com/alkevintan/omarchy-cointoss/commit/5e4dd9093154a16aab65f7e25656c6eb621055d0) | `com.aktivesolutions.cointoss`, `0.1.0` | Small, low-complexity QML/JavaScript bar-widget baseline |
| [omarchy-frame](https://github.com/SurreptitiousFabric/omarchy-frame) | [`8d1aaedfba49fcab28594e4a7fbaf6223385b247`](https://github.com/SurreptitiousFabric/omarchy-frame/commit/8d1aaedfba49fcab28594e4a7fbaf6223385b247) | `io.github.surreptitiousfabric.omarchy-frame`, `0.6.0` | Representative native/LAN and permission-heavy plugin |
| [omarchy-sonarchy](https://github.com/SurreptitiousFabric/omarchy-sonarchy) | [`37bcf08b452dbf36d150171ff3828e71832f3e02`](https://github.com/SurreptitiousFabric/omarchy-sonarchy/commit/37bcf08b452dbf36d150171ff3828e71832f3e02) | `io.github.surreptitiousfabric.sonarchy`, `4.1.0` | Representative service, setup, persistence, and migration-heavy plugin |
| [plug-and-prejudice](https://github.com/SurreptitiousFabric/plug-and-prejudice) | [`56dcee89f024c40e4244e6ea35c2fdb1fd40411a`](https://github.com/SurreptitiousFabric/plug-and-prejudice/commit/56dcee89f024c40e4244e6ea35c2fdb1fd40411a) | `io.github.surreptitiousfabric.plug-and-prejudice`, `0.1.0-dev` | Specialised scanner integration, self-analysis, and recursion subject |

Each selected repository declares the MIT License at the frozen revision. The
license permits fixture construction, but the additional publication and
signing rules below still apply.

### A dirty tree is not a revision

The local Plug & Prejudice checkout contains substantial uncommitted work
beyond its published `HEAD`. None of that work is frozen, described as public,
or eligible for corpus packaging. Its baseline is exactly the committed tree at
`56dcee89…`.

The same rule applies to every corpus source: a builder must reject a dirty
worktree unless the fixture ledger explicitly records a reviewed patch as a
derivative hostile fixture. A local branch name, `origin/main`, or directory
contents is not an immutable provenance identifier.

## Why these subjects

### Coin Toss: small ordinary baseline

The frozen Coin Toss commit has Git tree
`cd42b337c4288d2497d0bb7014bbc4708b081579`. Its manifest declares one bar
widget. The repository documents no native binary, daemon, installer, or
network requirement; it uses a small QML/JavaScript surface and ordinary local
tools and state. That makes it the low-complexity comparison point that the two
larger plugins cannot provide.

This is not a claim that Coin Toss is behaviour-free or safe. Plug & Prejudice
owns any expected behavioural findings. A Quo uses the source only to test
exact packaging, proof, structure, publisher, policy, and lifecycle outcomes.

### Omarchy Frame: native and LAN-sensitive behaviour

The frozen Omarchy Frame tree is useful because it is not a toy archive. It
contains QML, launchers, and native AMD64 and ARM64 binaries. Its intended
operation includes local-network discovery and television control, pairing and
locally stored state, image upload/cache behaviour, and fixed subprocess use
such as Zenity and Avahi tools.

This makes it suitable for testing:

- architecture-specific executable inventory;
- native-binary unknowns rather than invented source-level conclusions;
- LAN destination and device-control evidence;
- pairing-token/state and file-write descriptions;
- UI-to-native boundary reporting;
- update consent when a native binary or network scope changes.

The source baseline does not establish what every native code path does. Plug
& Prejudice owns the expected scanner result and must report that limitation
explicitly; A Quo only consumes and attributes the retained result.

### Omarchy Sonarchy: setup, service, and migration behaviour

The frozen Omarchy Sonarchy tree combines QML, Python, and shell code with a
persistent service. Its first-run setup creates a Python virtual environment
and installs hash-pinned dependencies. Its operation includes local-network
control, an inbound listener, public HTTPS access, persistent state/cache, and
subprocess or system mutation paths.

This makes it suitable for testing:

- multi-language analysis and coverage gaps;
- setup versus steady-state behaviour;
- dependency and generated-environment reporting;
- listener, outbound-network, subprocess, state, and persistence evidence;
- guarded update/migration and rollback behaviour;
- unknowns caused by external tools, network services, and runtime data.

Hash-pinned dependencies improve reproducibility of one setup input; they do
not make downloaded code safe or prove that installation happened offline.

### Plug & Prejudice: scanner integration and recursion

Plug & Prejudice is not an ordinary third target.

The frozen Plug & Prejudice revision already has a bounded Go
scanner/broker/report contract and an installed-plugin review panel. A Quo
intends to consume its native report through the sealed exact-snapshot
integration in [Plugin risk evidence](PLUGIN-RISK.md). Scanner-side pre-install
support is tracked in
[Plug & Prejudice #31](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/31).
The projects share their current repository owner, so this separation is
operational rather than organizationally independent.

That makes it a valuable specialised corpus subject for questions such as:

- what happens when the scanner analyses its own package;
- whether its exact native report bytes and digest remain intact;
- whether scanner identity, executable digest, and subject digest can be
  confused;
- whether the sealed-stream entry point can recurse into itself or invoke the
  signing daemon; and
- whether scanner errors and limitations remain fail-closed inputs to A Quo.

It is **not** the ordinary third representative target for issue #10. Treating
the scanner as that target would overfit the corpus to the evidence machinery
and under-test a small, ordinary declarative plugin.

## Frozen Frame lifecycle family

Four public ancestor commits provide source-level lifecycle cases without
inventing an upstream history:

| Revision | Manifest ID | Version | A Quo lifecycle role |
| --- | --- | --- | --- |
| [`33272eee645e1cb6dfcbf6c10f08b6502a2a63a8`](https://github.com/SurreptitiousFabric/omarchy-frame/commit/33272eee645e1cb6dfcbf6c10f08b6502a2a63a8) | `swa.frame` | `0.5.0` | prior release |
| [`be2b6cc5e0365b796dd866c8c92fa65d65492a7c`](https://github.com/SurreptitiousFabric/omarchy-frame/commit/be2b6cc5e0365b796dd866c8c92fa65d65492a7c) | `swa.frame` | `0.5.1` | valid same-ID increasing-version candidate |
| [`0e14e31f4f3786ad1b5f9e066ecf1f66743edcf3`](https://github.com/SurreptitiousFabric/omarchy-frame/commit/0e14e31f4f3786ad1b5f9e066ecf1f66743edcf3) | `io.github.surreptitiousfabric.omarchy-frame` | `0.6.0` | ID-change refusal candidate |
| [`8d1aaedfba49fcab28594e4a7fbaf6223385b247`](https://github.com/SurreptitiousFabric/omarchy-frame/commit/8d1aaedfba49fcab28594e4a7fbaf6223385b247) | `io.github.surreptitiousfabric.omarchy-frame` | `0.6.0` | equal-version, different-bytes refusal candidate relative to the early `0.6.0` tree |

The verified ancestry is `0.5.0` → `0.5.1` → early `0.6.0` → current
`0.6.0`. Once exact packages and proofs exist, `0.5.0` → `0.5.1` is the normal
update case; the reverse is a downgrade refusal; `0.5.1` → early `0.6.0` is an
ID-change refusal; and early → current `0.6.0` is an equal-version refusal.
These are package/lifecycle expectations, not behavioural scanner findings.

## What is frozen and what is not

### Frozen now

- repository URL and full public commit ID for each subject above;
- the committed source tree identified by that commit;
- manifest identity and version observed in that tree;
- the real Frame source-history cases above, including one same-ID increasing
  version pair;
- its broad corpus role;
- the fixture-construction, licensing, and evidence rules in this document.

### Not available and therefore not guessed

- canonical Omarchy package bytes or their SHA-256 digests;
- proof-bundle bytes, signer persona roots, or signing-key fingerprints;
- a pinned package-builder implementation/version and reproducible-build
  recipe;
- generated analysis-stream bytes, byte lengths, and digests for the frozen
  source packages;
- recorded Omarchy permission requests or policy outcomes;
- clean-system install, enablement, update, rollback, or uninstall results;
- performance baselines and resource-limit measurements;
- written permission to publish derivative hostile packages signed by any
  production persona.

No selected Coin Toss or Sonarchy history inspected here supplied another
verified earlier same-ID version pair. That absence is recorded rather than
filled with an invented upstream release.

## Fixture ledger

Every generated corpus artifact must have a machine-readable ledger entry.
The format may be chosen with the corpus implementation, but it must cover:

```text
fixture_id
purpose
source_repository
source_commit
source_tree_clean
source_license
derivative_patch_sha256          or null
builder_repository
builder_commit
builder_environment
target_architecture
package_sha256
package_size
manifest_sha256                  or null
plugin_id                        or null
plugin_version                   or null
proof_sha256                     or null
signer_test_persona_root         or null
base_fixture_id                  or null
update_from_fixture_id           or null
network_phase                    offline | controlled_integration
expected_parser_result
expected_structural_evidence
native_report_sha256             or null
native_report_schema             or null
scanner_identity                 or null
expected_scanner_binding_result
expected_scanner_status
expected_policy_result
expected_install_result
expected_update_result
expected_rollback_result
expected_residue
publication_permission_record   or null
```

The ledger records expectations precisely enough that a rejection is not
silently changed into an acceptance during a test update. Digests are computed
from final bytes, never copied from a mutable pathname before packaging.

Secrets, signing-key locators, device tokens, pairing tokens, recovery data,
private keys, and generated user state never appear in a fixture or ledger.

## Licensing, permission, and signing rules

Open-source permission and cryptographic endorsement answer different
questions. The following rules apply even to MIT-licensed owner-controlled
repositories:

1. Preserve license and copyright notices in derived fixtures as the license
   requires.
2. Obtain explicit written approval from the repository owner before
   publishing a derivative hostile fixture, public proof bundle, or signature
   that could reasonably be read as the owner endorsing those bytes.
3. Use a clearly fictional, non-production A Quo persona dedicated to hostile
   tests. Its label and documentation must say `TEST FIXTURE — NOT ENDORSED`.
4. Never use a production publisher persona, official release key, or a key
   that consumers may already trust.
5. Never commit a private key. CI creates ephemeral keys or uses reviewed
   non-secret public fixtures whose private half is unavailable.
6. Do not include live device identifiers, credentials, addresses, pairing
   tokens, user content, or captured home-directory state.
7. Keep hostile variants in a clearly separate path and repository context;
   do not open pull requests that make them look like upstream product changes.
8. Record the source commit, complete patch digest, builder revision, and final
   package digest. A descriptive filename is insufficient provenance.
9. A valid test signature is labelled only as integrity/persona evidence. It
   must never be presented as “safe,” “approved,” or “official.”

If public permission is absent, keep the derivative fixture local and generate
it deterministically during tests from the licensed source plus a reviewed
patch. Do not publish its bytes or proof.

## Base test matrix

Each representative source eventually supplies clean, deterministic cases for:

| Phase | Required evidence |
| --- | --- |
| Build | builder revision, clean source commit, final digest, reproducibility result |
| Verify | exact proof outcome and persona/publisher dimension |
| Inspect | manifest, archive counts/types/modes, executable/native inventory, unknowns |
| Bind scanner evidence | exact native-report bytes/digest, scanner identity, status, exact subject binding, explicit unavailable/error state |
| Consent | full identifiers, findings/unknowns, local policy, exact action; cancel is safe |
| Install | clean-system destination and immutable approved snapshot |
| Enable | A Quo makes no enable call; exact reference observations and the separate Omarchy decision are recorded |
| Update | old/new exact snapshots, continuity, version/ID rule, compatible retained-report comparison or explicit indeterminate state |
| Roll back | state and package restoration under an explicit rollback policy |

Frame and Sonarchy must run on every architecture for which A Quo claims that
plugin/package journey is supported. A native binary for an unexercised
architecture remains an explicit coverage gap; upstream architecture claims do
not silently expand A Quo's support matrix.

## Hostile variants

Hostile variants are deterministic patches applied to a frozen source. Each
variant changes one primary property unless its purpose is explicitly an
interaction test.

### Package and structure variants

- absolute, parent-traversal, empty, duplicate, and Unicode-confusable paths;
- symlink, hard link, device, FIFO, socket, sparse/oversized, and unsupported
  archive entries;
- excessive entry count, path length, manifest size, compression ratio, and
  total extracted size;
- manifest missing, duplicated, malformed, wrong type, unknown ordinary field
  with the current expected ignore behavior, mismatched ID/version, or hostile
  display string. No “unknown critical field” case exists until Omarchy defines
  a critical-extension convention;
- executable mode added to data, mode removed from an entrypoint, and native
  binary hidden behind misleading extension;
- package mutation after proof verification and pathname replacement during
  inspection/install.

These primarily test A Quo's built-in bounded parser and exact-snapshot use.
They must not be delegated to an external scanner.

### Native-report consumer-boundary variants

The provider adapter owns native-schema cases: oversized or truncated reports,
duplicate fields, unsupported schema or enums, contradictory native status,
hostile report strings, and provider-specific comparison of findings,
limitations, errors, and coverage. For the first integration, those tests live
with `a-quo-provider-plug-and-prejudice` and Plug & Prejudice rather than in A
Quo core.

A Quo core owns only the opaque integration boundary:

- adapter crash, timeout, containment failure, or explicit integration status;
- absent, malformed, oversized, stale, or substituted opaque report bindings;
- invalid package/stream subject binding, including a report for an installed
  copy substituted for the approved pre-install snapshot;
- changed adapter/broker/scanner/ruleset component identity with identical
  plugin bytes;
- incomplete, unsupported, error, and not-run states as explicit policy
  inputs; and
- binding, policy, consent, and installation races.

Expected adapter outcomes distinguish an accepted native report from invalid
provider-specific data. Expected core outcomes distinguish accepted opaque
binding, invalid binding, indeterminate comparison, explicit integration
status, and local policy decision. A test must never expect “safe.”

Source variants for new outbound destinations, file access, subprocesses,
privilege, persistence, downloaded code, dynamic imports, `eval`, opaque
native binaries, obfuscation, and unsupported syntax may reuse the frozen
source revisions, but their expected behavioural detection belongs in Plug &
Prejudice. A Quo tests only the resulting retained report's binding and policy
effect.

### Update and rollback variants

- version downgrade, same version with different bytes, plugin-ID change, and
  publisher-continuity break;
- an adapter-attributed comparison reporting material behavioural expansion
  with unchanged plugin prose;
- an adapter-attributed removed finding accompanied by reduced Plug &
  Prejudice coverage;
- broker/scanner/ruleset change with identical plugin bytes;
- approval of one digest followed by installation of another;
- interrupted update at each atomic boundary;
- rollback to a valid prior package with incompatible new state;
- a future removal workflow that names paths outside its owned destination
  (a #9 product-hardening fixture, not a current A Quo command or #10 freeze
  gate).

Normal update tests require exact same-ID increasing versions created for that
purpose; the unavailable pairs listed above may not be approximated by changing
the expected value in a test.

## Plug & Prejudice recursion cases

Scanner self-analysis is kept separate from the representative matrix and must
cover at least:

1. the exact Plug & Prejudice package is the subject, not its currently
   installed directory;
2. the broker/scanner/ruleset and native report digests are preserved;
3. analysing its own source does not cause recursive scanner invocation;
4. no path reaches the A Quo signing daemon or consent authority;
5. a self-reported clean/complete result has no special authority;
6. invalid self-analysis is an error/unknown, not a bypass; and
7. the Plug & Prejudice adapter retains and validates the native report, while
   A Quo core binds only its opaque identity/status and never executes its
   fields or translates it into a second behavioural graph.

## Layered acceptance without circular dependencies

The corpus, scanner integration, and product journey use the same fixtures but have
different completion gates. A later layer may depend on an earlier one; the
earlier layer never depends on results from the later layer.

### Layer 1: immutable package/proof corpus (#10)

The initial #10 corpus is frozen when:

- a pinned builder creates one canonical package for each source and hostile
  patch, records whether independent rebuilding is byte-identical, and explains
  every difference rather than silently choosing new bytes;
- the ledger contains exact source, patch, builder, architecture, package,
  manifest, proof, and fictional test-persona identifiers plus expected parser
  and structural outcomes;
- normal same-ID increasing-version update pairs exist;
- owner permission and license handling are recorded for every published
  derivative fixture;
- package/manifest/proof hostile variants have exact expected accept/reject
  outcomes, including explicit unknowns; and
- fixtures are generated offline, contain no secret, and never imply that a
  signature means safe.

This layer does not require Plug & Prejudice integration, a trusted install prompt,
accessibility bridge, successful installation, or clean-system product result.
It supplies immutable inputs to those later tests.

### Layer 2: scanner integration conformance (#8 and Plug & Prejudice #31)

After Layer 1 is frozen, Plug & Prejudice owns scanner conformance and the
behavioural expectations for each fixture. A Quo records the exact broker,
scanner, ruleset, native-report schema/digest, resource-limit/containment
result, package/analysis-stream subject, and expected binding, comparison, and
policy outcome. Crash, timeout, invalid-report, wrong-subject, recursion,
changed-scanner, and coverage-regression consumer cases run offline.

Passing this layer shows that A Quo consumed and bound one supported native
report correctly. It does not independently establish that Plug & Prejudice
found every relevant behaviour. Controlled network integration, if any, is a
separately labelled Plug & Prejudice result and never changes the frozen
package bytes.

### Layer 3: product journey (#6/#7/#9)

After the relevant Layer 2 result exists, clean-system tests may exercise
trusted presentation, keyboard and assistive-technology behavior, install,
enablement, update, rollback, interruption, and any future removal workflow.
Those results belong to the product issues and
[accessibility contract](ACCESSIBILITY.md); their absence does not unfreeze or
invalidate the source/package corpus.

At present, the representative and lifecycle revisions above are only a pinned
**source baseline**. Layer 1 is incomplete because the builder, canonical
packages/proofs, fixture ledger, hostile variants, and publication-permission
records do not yet exist.
