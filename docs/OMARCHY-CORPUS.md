# Owned Omarchy plugin corpus

Status: **source baseline and hostile-fixture design; package/proof corpus and
clean-system results not yet frozen**

This document defines the initial repository-owner-controlled corpus for A Quo
Omarchy package, inspection, update, and future risk-evidence testing. It fixes
the source revisions that can be verified today, records what is still absent,
and sets rules for constructing hostile variants without implying that a
signature or test fixture endorses unsafe code.

The corpus supports issues #7–#10. It is not evidence that those issues are
complete. In particular, no canonical package bytes, A Quo proof bundles,
clean-system install results, or same-plugin update pairs are frozen here yet.

## Frozen source baseline

All revisions below were checked both in the local clone and at the public
GitHub commit URL. Only committed trees are in scope.

| Corpus subject | Frozen revision | Manifest identity and version | Intended role |
| --- | --- | --- | --- |
| [omarchy-frame](https://github.com/SurreptitiousFabric/omarchy-frame) | [`8d1aaedfba49fcab28594e4a7fbaf6223385b247`](https://github.com/SurreptitiousFabric/omarchy-frame/commit/8d1aaedfba49fcab28594e4a7fbaf6223385b247) | `io.github.surreptitiousfabric.omarchy-frame`, `0.6.0` | Representative native/LAN and permission-heavy plugin |
| [omarchy-sonarchy](https://github.com/SurreptitiousFabric/omarchy-sonarchy) | [`37bcf08b452dbf36d150171ff3828e71832f3e02`](https://github.com/SurreptitiousFabric/omarchy-sonarchy/commit/37bcf08b452dbf36d150171ff3828e71832f3e02) | `io.github.surreptitiousfabric.sonarchy`, `4.1.0` | Representative service, setup, persistence, and migration-heavy plugin |
| [plug-and-prejudice](https://github.com/SurreptitiousFabric/plug-and-prejudice) | [`56dcee89f024c40e4244e6ea35c2fdb1fd40411a`](https://github.com/SurreptitiousFabric/plug-and-prejudice/commit/56dcee89f024c40e4244e6ea35c2fdb1fd40411a) | `io.github.surreptitiousfabric.plug-and-prejudice`, `0.1.0-dev` | Specialised provider self-analysis and recursion subject |

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

The source baseline does not establish what every native code path does. A risk
provider must report that limitation explicitly.

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

### Plug & Prejudice: provider recursion, not an ordinary third target

The frozen Plug & Prejudice revision already has a bounded Go
scanner/broker/report contract and an installed-plugin review panel. A Quo
intends to consume it later as an optional, separately executed analysis
provider through the exact-snapshot adapter in
[Plugin risk evidence](PLUGIN-RISK.md). It shares A Quo's current repository
owner, so this separation is operational rather than organizationally
independent.

That makes it a valuable specialised corpus subject for questions such as:

- what happens when the scanner analyses its own package;
- whether its native report and the A Quo envelope remain distinct;
- whether provider identity, executable digest, and subject digest can be
  confused;
- whether the adapter can recurse into itself or invoke the signing daemon;
- whether provider errors and limitations remain fail-closed.

It is **not** the ordinary third representative target for issue #10. Treating
the scanner as that target would overfit the corpus to the evidence machinery
and under-test a small, ordinary declarative plugin.

## Explicitly missing third representative target

The initial representative matrix still needs a repository-owner-controlled,
small, primarily declarative Omarchy plugin with no native executable, service,
installer, or network requirement. No exact public revision matching that role
was verified during this freeze, so this document does not invent one.

Before issue #10 can meet its three-representative-plugin acceptance criterion,
that target must be selected and frozen by full public commit ID, manifest
identity/version, license, and repository-owner permission. It should exercise
the low-risk baseline and make false-positive pressure visible.

## What is frozen and what is not

### Frozen now

- repository URL and full public commit ID for each subject above;
- the committed source tree identified by that commit;
- manifest identity and version observed in that tree;
- its broad corpus role;
- the fixture-construction, licensing, and evidence rules in this document.

### Not available and therefore not guessed

- canonical Omarchy package bytes or their SHA-256 digests;
- proof-bundle bytes, signer persona roots, or signing-key fingerprints;
- a pinned package-builder implementation/version and reproducible-build
  recipe;
- exact analysis-stream schema, byte length, and digest for the future risk
  interface;
- recorded Omarchy permission requests or policy outcomes;
- clean-system install, enablement, update, rollback, or uninstall results;
- performance baselines and resource-limit measurements;
- an exact same-manifest-ID, increasing-SemVer update pair for any selected
  representative subject;
- a frozen third ordinary representative plugin;
- written permission to publish derivative hostile packages signed by any
  production persona.

An older Omarchy Frame revision uses a different plugin ID (`swa.frame`). It may
later test ID migration or refusal, but it is not a normal same-ID update pair.
No selected Sonarchy or Plug & Prejudice history inspected here supplied a
verified earlier manifest version suitable for the required update pair.

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
expected_provider_status
expected_unknowns
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
| Analyse | provider identity/version, status, coverage, findings, limitations, subject binding |
| Consent | full identifiers, findings/unknowns, local policy, exact action; cancel is safe |
| Install | clean-system destination and immutable approved snapshot |
| Enable | no automatic enablement unless separately authorized |
| Update | old/new exact snapshots, continuity, version/ID rule, risk/permission delta |
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

### Behaviour and risk-evidence variants

- new outbound destination, wildcard destination, LAN scan, or inbound listener;
- new write outside declared state/cache, recursive home access, or secret-like
  file read;
- new arbitrary subprocess, shell interpolation, privilege escalation request,
  or desktop/session mutation;
- new autostart, long-lived service, scheduled work, or persistence mechanism;
- new downloaded/executed code, dynamic import, `eval`, opaque native binary,
  or architecture-specific payload;
- provider crash, timeout, oversized report, duplicate field, unknown enum,
  misleading severity, missing coverage category, or invalid subject digest;
- report for an installed copy substituted for the approved pre-install
  snapshot;
- findings containing terminal escapes, bidi/default-ignorable text, markup,
  very long paths, and missing-glyph sequences.

Expected outcomes distinguish structural fact, provider fact, inference,
unknown, error, and local policy decision. A test must never expect “safe.”

### Update and rollback variants

- version downgrade, same version with different bytes, plugin-ID change, and
  publisher-continuity break;
- permission or risk expansion with unchanged prose description;
- removed finding accompanied by reduced provider coverage;
- provider/scanner-policy change with identical plugin bytes;
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

Provider self-analysis is kept separate from the representative matrix and must
cover at least:

1. the exact Plug & Prejudice package is the subject, not its currently
   installed directory;
2. the provider executable and native report digests are preserved;
3. analysing its own source does not cause recursive scanner invocation;
4. no path reaches the A Quo signing daemon or consent authority;
5. a self-reported clean/complete result has no special authority;
6. invalid self-analysis is an error/unknown, not a bypass;
7. the A Quo adapter remains a closed translator rather than executing fields
   from the native report.

## Layered acceptance without circular dependencies

The corpus, analyzer, and product journey use the same fixtures but have
different completion gates. A later layer may depend on an earlier one; the
earlier layer never depends on results from the later layer.

### Layer 1: immutable package/proof corpus (#10)

The initial #10 corpus is frozen when:

- the missing small declarative third target is selected by exact public
  revision;
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

This layer does not require a risk provider, trusted install prompt,
accessibility bridge, successful installation, or clean-system product result.
It supplies immutable inputs to those later tests.

### Layer 2: analyzer conformance (#8/#9)

After Layer 1 is frozen, each supported analyzer/adapter records its exact
provider, policy/ruleset, adapter, resource-limit profile, subject/analysis-stream digest,
coverage, findings, limitations, errors, and expected update delta for the
fixtures. Provider crash, timeout, invalid-report, wrong-subject, recursion, and
coverage-regression cases run offline. Controlled network integration, if any,
is a separately labelled result and never changes the frozen package bytes.

### Layer 3: product journey (#6/#7/#9)

After the relevant Layer 2 result exists, clean-system tests may exercise
trusted presentation, keyboard and assistive-technology behavior, install,
enablement, update, rollback, interruption, and any future removal workflow.
Those results belong to the product issues and
[accessibility contract](ACCESSIBILITY.md); their absence does not unfreeze or
invalidate the source/package corpus.

At present, the three revisions at the top are only an owned **source
baseline**. Layer 1 is incomplete because the third ordinary target, pinned
builder, canonical packages/proofs, update pairs, and fixture ledger do not yet
exist.
