# Public evidence index

This index retains dated implementation, CI, artifact, and review coordinates
that are useful for reproducing historical A Quo claims. Normative behavior is
defined by the linked current contracts, not by this chronology. An old green
run does not establish that current code passes, that a dependency is still
valid, or that any artifact is safe or release-ready.

GitHub issues remain the authoritative acceptance records. This file is the
compact repository index requested by issue #45 so README, ROADMAP, the
maturity summary, and normative contracts do not each carry the same history.

## Continuity, archive, and root-distribution evidence

| Reviewed outcome | Public implementation | Hosted evidence | Acceptance record | Bounded meaning |
| --- | --- | --- | --- | --- |
| Initial 0.x maturity audit | [`b1d5c9c2d5fb35da7e5e920695fb58d82b8e3dfb`](https://github.com/SurreptitiousFabric/a-quo/commit/b1d5c9c2d5fb35da7e5e920695fb58d82b8e3dfb) | Initial audit reviewed 2026-08-28 | [#5](https://github.com/SurreptitiousFabric/a-quo/issues/5) | Baseline governance and issue-by-issue reconciliation, not product assurance |
| One-archive comparison (#27) and direct activation (#29) | [`57be5e25096070c667c7891a946ce4e3e2a4bef4`](https://github.com/SurreptitiousFabric/a-quo/commit/57be5e25096070c667c7891a946ce4e3e2a4bef4) | [run 33259607842](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33259607842): check, dependency audit, ASan/LSan fuzz | [#27 record](https://github.com/SurreptitiousFabric/a-quo/issues/27#issuecomment-5463238609), [#29 record](https://github.com/SurreptitiousFabric/a-quo/issues/29#issuecomment-5463238621) | Bounded comparison and direct materialization prototypes; no general fork resolution or production claim |
| Terminal archive hydration (#28) | [`9cef13b89c88d29aefeda0f91c337f52da6d3c0d`](https://github.com/SurreptitiousFabric/a-quo/commit/9cef13b89c88d29aefeda0f91c337f52da6d3c0d) | [run 33263700384](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33263700384): check, dependency audit, ASan/LSan fuzz | [#28 record](https://github.com/SurreptitiousFabric/a-quo/issues/28#issuecomment-5463640730) | Exact terminal projection with zero authority; not trusted pin acquisition or product hardening |
| Recovery archive activation (#30) | [`9dc67c6c949e7313adeefe1fedfee8a8c5f3a87a`](https://github.com/SurreptitiousFabric/a-quo/commit/9dc67c6c949e7313adeefe1fedfee8a8c5f3a87a) | [run 33266914822](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33266914822): check, dependency audit, bounded fuzz | [#30 record](https://github.com/SurreptitiousFabric/a-quo/issues/30#issuecomment-5464001821) | One exact recovery extension and successor activation; not general recovery UX or independent-holder evidence |
| Terminal replay and future-issued-leaf assurance (#31/#32) | Implementation [`b2dab9a7b3c9479b781a22a86f19c8a115c7d190`](https://github.com/SurreptitiousFabric/a-quo/commit/b2dab9a7b3c9479b781a22a86f19c8a115c7d190); evidence-only evaluation [`9190d7a565b847de1267e2b29bdb0033d7600e8e`](https://github.com/SurreptitiousFabric/a-quo/commit/9190d7a565b847de1267e2b29bdb0033d7600e8e) | [run 33411807840](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33411807840): check, dependency audit, bounded fuzz, portable-root jobs | [#31 record](https://github.com/SurreptitiousFabric/a-quo/issues/31#issuecomment-5481132111), [#32 record](https://github.com/SurreptitiousFabric/a-quo/issues/32#issuecomment-5481132090) | Path-specific P3 regression evidence; no trusted time, external witness, or broader maturity claim |
| Persona-root distribution (#3) | [`1637cb7b55ee330a685e033cba311fb978b024ec`](https://github.com/SurreptitiousFabric/a-quo/commit/1637cb7b55ee330a685e033cba311fb978b024ec) | [run 33271292045](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33271292045): check, audit, fuzz, Linux/macOS/Windows portable-format matrix | [#3](https://github.com/SurreptitiousFabric/a-quo/issues/3) | Bounded portable cards and pin comparisons; no proof that channels were independent |
| Threshold recovery hardening checkpoint (#4) | [`ec92f50fa8d32b0cf1b9a93f952296e49290bc08`](https://github.com/SurreptitiousFabric/a-quo/commit/ec92f50fa8d32b0cf1b9a93f952296e49290bc08) | [run 33271570545](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33271570545): check, audit, fuzz, portable-root jobs | [#4 record](https://github.com/SurreptitiousFabric/a-quo/issues/4#issuecomment-5464514203) | Entry to Hardening; the issue's remaining ceremony, holder, UX, and external-review gates stay open |

The current claim-to-evidence summary and next unmet gate for each issue are in
[MATURITY-AUDIT.md](MATURITY-AUDIT.md). Status terms are defined only in
[MATURITY.md](MATURITY.md).

## Maturity reconciliation checkpoints

The original 2026-08-28 audit required and received these Project field
changes:

- `#1`: Implementing → Prototype complete and Defined → Met;
- `#2`: Prototype complete → Implementing;
- `#5`: Design → Done and Needs definition → Met;
- `#9`: Prototype complete → Implementing;
- `#14`: Prototype complete → Implementing;
- `#17`: Prototype complete → Implementing; and
- `#26`: Design → Implementing.

Later issue-specific records produced these additional changes:

- `#27`: Implementing → Prototype complete and Defined → Met;
- `#28`: Design → Prototype complete and Defined → Met;
- `#29`: Design → Prototype complete and Defined → Met;
- `#30`: Design → Prototype complete and Defined → Met;
- `#31`: Backlog → Prototype complete and Defined → Met;
- `#32`: Backlog → Prototype complete and Defined → Met;
- `#3`: Design → Prototype complete and Defined → Met; and
- `#4`: Prototype complete → Hardening, with Acceptance evidence remaining
  Defined.

The 2026-08-30 product-boundary audit moved `#6`, `#8`, and `#10` from Backlog
to Design while their Acceptance evidence remained Defined. The later
deterministic six-revision corpus builder and unsigned same-host observation
ledger moved `#10` from Design to Implementing, still with Defined evidence.
That checkpoint did not establish portable signatures, behavioural review,
lifecycle execution, or safety.

Issues `#3` and `#27` through `#32` closed with Met evidence for their frozen
bounded outcomes while retaining Prototype complete Project status. The
broader `#26` outcome remained open; closing a child prototype did not complete
multi-candidate or existing-live fork handling, product consent and UX,
hardening, or external review.

## AArch64 candidate and selection observations

The candidate directories in this section were ignored, private local state;
their contents were not committed, published, or promised durable retention.
The repository therefore preserves only the chronological record below, not
independently replayable evidence. Current acquisition, verification, and
nonclaim requirements are normative only in
[PACKAGING.md](PACKAGING.md#candidate-only-bootstrap-acquisition).

| Boundary | Dated observation | Retained coordinate and bounded meaning |
| --- | --- | --- |
| Bootstrap candidate acquisition | On 2026-08-31, the first fresh attempt stopped at the first release-asset redirect and remained `INCOMPLETE`, exposing an over-broad control-character check. A second fresh attempt acquired 15 objects totalling 50,718 bytes through one direct raw-key response and 14 one-hop `release-assets.githubusercontent.com` responses, verified seven detached-signature pairs, and separately verified the three signed descriptor records and their profile bindings. | The 37-line `authority=none` receipt had SHA-256 `fc4f61d09d214f0c0594fc30d57dd246ad370e5d703c8e5263e0432741f5b491`. Both directories were ignored and unpublished; this was not trusted input, current publisher authorization, or target arming. |
| Ubuntu OCI candidate acquisition | On 2026-08-31, the first fresh attempt failed closed before accepting config bytes because the closed redirect policy did not yet include Docker's exact `production.cloudfront.docker.com` endpoint. After adding only that exact host while retaining the other redirect, authorization-stripping, size, and digest gates, the second attempt acquired and separately verified the four-object descriptor chain, exactly 28,896,414 compressed bytes, and the DiffID. | The completed 27-line `authority=none` receipt had SHA-256 `330874fa539c10a591fdd206d28f990bb4e29a8c4eca62410e31fcb44b50543e`. Both directories were ignored private observations, not published inputs or authority evidence. |
| Ubuntu APT candidate acquisition | Six opt-in attempts on 2026-08-31 used snapshot `20260831T000000Z`. Attempts 01–03 remained `INCOMPLETE` while exposing the single-UID sandbox constraint, absent snapshot-bound ports targets, and verifier grammar defects. Attempt 04 completed. After stricter layer-extraction and initial-cache boundaries, attempt 05 failed closed when APT returned success without index targets; attempt 06 completed with bounded diagnostic handling. | Both complete candidates contained the same 110,637,976 file bytes: 19 indexes, 93 packages, nine state records, and one CA bundle. Their 122-object manifests, 93-entry no-removal solver plans, and all 128 files matched on the same host. The shared 38-line receipt had SHA-256 `c99f29429d8d6f87c0651154dee28153af4b6d6c0c47908ca767067d3f1f5d13`. All directories were ignored and not durably retained; this was not independent reproduction or class-02 closure. |
| Reviewed OCI-lock verification | One local read-only invocation verified the previously retained 28,896,414 object bytes from sealed snapshots and recomputed a 103,204,352-byte uncompressed layer with the locked DiffID. | The ignored bytes were neither changed nor published. Losing the local directory leaves the committed lock without locally retained bytes. No image, rootfs, package transaction, VM, service, consent flow, or clean-system result was created. |

## Hosted x86_64 package evidence

These records belong to the separate physical x86_64 lane. They never satisfy
an AArch64 gate. The current normative target mapping, container policy, and
remaining stages are in [PACKAGING.md](PACKAGING.md). Exact machine-readable
coordinates remain frozen in the referenced locks and workflows.

### Authority-none NEEDED observation

| Field | Exact historical value |
| --- | --- |
| Source | [`cbbe29b6bc76949182777d7ec10dc73a219f7592`](https://github.com/SurreptitiousFabric/a-quo/commit/cbbe29b6bc76949182777d7ec10dc73a219f7592) |
| Workflow | [run 33447883884](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33447883884), attempt 1 |
| Artifact | `9778938759`, `x86-needed-observation-cbbe29b6bc76949182777d7ec10dc73a219f7592-1` |
| Raw ZIP SHA-256 | `97e2dac4a83e8f43f540199bb3b140532159001442ece926b32c9c3d829af394` |
| Package SHA-256 | `52394e2115b0b235dcad849bb91856725e945579266628f0f74fd9e5d64fa264` |
| Source archive SHA-256 | `fb43ea0020979a807fa7b49dd30fb014daadf6c67d5154dd735a1c3676065f74` |
| Frozen record | [`a-quo-x86_64-needed-observation-cbbe29b6-v1.lock`](../packaging/evaluation-input-locks/a-quo-x86_64-needed-observation-cbbe29b6-v1.lock) |

This run produced an uninstalled x86_64 package and an exact ELF interpreter
and `DT_NEEDED` observation. The original receipt was nonaccepting and granted
no authority. A later owner review accepted only those exact ELF facts as
static package policy; it did not retroactively turn the observation into
provenance, signature, physical-target, native-hardware, or stage-4 evidence.
The historical workflow can dispatch only at its exact source commit, and the
hostile replay uses that immutable source rather than current policy code.

### Hosted stage-4 static acceptance

| Field | Exact historical value |
| --- | --- |
| Source | [`ee47d7f1e4432ea3b3edab25dc0875b7133d5733`](https://github.com/SurreptitiousFabric/a-quo/commit/ee47d7f1e4432ea3b3edab25dc0875b7133d5733) |
| Workflow | [run 33456949816](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33456949816) |
| Artifact | `9781997778`, `x86-static-acceptance-ee47d7f1e4432ea3b3edab25dc0875b7133d5733-1` |
| Raw ZIP | 19,036,458 bytes; SHA-256 `15e24d068cd31b2de8cd23730303b5ad95a5d534d96c76076ddc015558d34f75` |
| Package SHA-256 | `75db0ad706aac8c69fefa29c0d27029b80796d665f452e296d0baae09ac25e11` |
| Frozen F1 record | [`a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock`](../packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock) |
| Acceptance record | [issue #36, comment 5487053185](https://github.com/SurreptitiousFabric/a-quo/issues/36#issuecomment-5487053185) |

All four retained ledgers replayed after download. The accepted claim is only
uninstalled hosted stage-4 static package evidence for those exact bytes. It
does not establish source-to-binary provenance, lifecycle behavior, a physical
target, native hardware, AArch64 compatibility, or stage-6 authorization.

### Hosted stage-5 isolated lifecycle

| Field | Rejected attempt | Accepted attempt |
| --- | --- | --- |
| Source | [`5cb01e1ab9a7cb02ef367e83bf6321da2d85d31a`](https://github.com/SurreptitiousFabric/a-quo/commit/5cb01e1ab9a7cb02ef367e83bf6321da2d85d31a) | [`3f2d82edefd418debee63b7d5946c2cc9923aca3`](https://github.com/SurreptitiousFabric/a-quo/commit/3f2d82edefd418debee63b7d5946c2cc9923aca3) |
| Workflow | [run 33462058642](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33462058642), failure | [run 33463360533](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33463360533), success |
| Result | Failed closed before container creation because dependency acquisition populated the lifecycle target; no accepted artifact | Completed private fakeroot/libalpm install F1, upgrade to F2, remove, and reinstall F2 |
| Artifact | None accepted | `9784174842` |
| Raw ZIP SHA-256 | Not applicable | `5bfe9222af422de71ec6b87354681b47bd9775bb1959ee6dcfc5bb2f73b62cd3` |
| F2 package SHA-256 | Not applicable | `f10a96be2d5c7281cf9399fa92eecc09abe100b8dbdb60153a3ffa8e9cc361ab` |

The accepted run used the frozen F1 artifact in a fifth read-only mount and a
distinct descendant F2 in the reviewed non-root, network-none container. All
four ledgers, the source archive, production package verifier, and captured
pre-start policy replayed. Post-exit inspect bytes were not retained for
independent replay. This is hosted architecture-matched alternate-root stage-5
evidence only: no real Pacman/root/system mutation, physical Intel target,
installed service or consent flow, Omarchy plugin lifecycle, provenance,
signature, AArch64 credit, or stage-6 authorization was established.

## AArch64 joined-lifecycle checkpoints

| Evidence | Exact coordinate | Meaning and limit |
| --- | --- | --- |
| Synthetic fixture source | [`54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04`](https://github.com/SurreptitiousFabric/a-quo/commit/54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04) | Source of inert, non-loadable v1/v2 fixture subtrees |
| Fixture packages | v1 SHA-256 `2141fc8de82f40ac6a44b412e640846667b0cc78fd7b83280d157c24f87eaa71`; v2 SHA-256 `806966a0bf27e902fc1e059c2a7004c72afcce085039c568c4ac5e17fead130a` | Deterministically rebuilt local fixture bytes; not signatures, publication, safety, or lifecycle evidence |
| Joined input lock publishing checkpoint | [`f1608a1c90e667644e936bc688f766e911c18262`](https://github.com/SurreptitiousFabric/a-quo/commit/f1608a1c90e667644e936bc688f766e911c18262) | Revision at which the class-10 lock was frozen |
| Joined lock | [`a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock`](../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock), SHA-256 `c7520d646232f47c8990a04eb9cd2992c2ffba204843223f6e107b138b02d545` | Exact selection only; external authentication and durable retention remain caller responsibilities |
| Reviewed policy checkpoint | [`0e1fcb40c8b0d2e160ca8c139f4a5b6efb9a7400`](https://github.com/SurreptitiousFabric/a-quo/commit/0e1fcb40c8b0d2e160ca8c139f4a5b6efb9a7400) | Policy revision bound by the joined lock; not build or evaluator authority |

The current commands and pre-mutation use of these inputs are specified in the
[joined fixture and lifecycle sections of PACKAGING.md](PACKAGING.md#deterministic-joined-lifecycle-fixture-inputs).

## Review-debt cleanup

| Issue | Merged change | Exact-head checks | Bounded meaning |
| --- | --- | --- | --- |
| [#44 typed exact-input locks and reports](https://github.com/SurreptitiousFabric/a-quo/issues/44) | [PR #53](https://github.com/SurreptitiousFabric/a-quo/pull/53), squash commit [`b5f611afed3e65a299a5a61e33fb1f2873c18f1f`](https://github.com/SurreptitiousFabric/a-quo/commit/b5f611afed3e65a299a5a61e33fb1f2873c18f1f) | [run 33502887626](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33502887626): required check, fuzz, Linux, macOS, Windows | Shared typed lock/report structures and genuinely identical archive/digest plumbing with explicit OCI, AAVMF, ALARM, and QEMU policy; no claim of safety, provenance, or release readiness |

## Retention and updates

- Do not delete an evidence record merely because a newer implementation
  exists. Add the successor and state what the earlier record still means.
- Keep mutable current status out of this file; use the public Project and
  `MATURITY-AUDIT.md`.
- Keep machine-enforced current pins in locks, profiles, workflows, or fixture
  registries. This index is explanatory and must not become a second parser
  authority.
- A link to a CI run reports what GitHub recorded for that run. It is not an
  independent security review and does not authenticate unrelated artifacts.
