# A Quo 0.x maturity audit

This is the first issue-by-issue audit under the normative
[maturity and acceptance-evidence policy](MATURITY.md). The original audit
covered all 25 milestone items in the
[Witness Me!](https://github.com/users/SurreptitiousFabric/projects/9) Project
on 2026-08-28 and reviewed repository evidence through public commit
`b1d5c9c2d5fb35da7e5e920695fb58d82b8e3dfb`. The policy, templates, and initial
audit became additional evidence in their later publishing revision. The
terminal-revocation updates to rows #2 and #4 and the archive comparison/direct
activation work represented by rows #26 through #30 were reviewed separately
on 2026-08-29. The bounded #27 comparison and #29 direct-activation outcomes
are public at exact revision
`57be5e25096070c667c7891a946ce4e3e2a4bef4`. At that revision,
[hosted CI run 33259607842](https://github.com/SurreptitiousFabric/a-quo/actions/runs/33259607842)
passed the complete check and dependency-audit job plus the independent
ASan/LSan fuzz job. The dated public evidence records are attached to
[#27](https://github.com/SurreptitiousFabric/a-quo/issues/27#issuecomment-5463238609)
and
[#29](https://github.com/SurreptitiousFabric/a-quo/issues/29#issuecomment-5463238621).

The audit evaluates each issue's stated outcome. A component's earlier
prototype does not satisfy a later hardening issue. `Defined` means the issue
has testable completion criteria but they are not all met.

The `Audited Status` column states the status supported by the cited public
evidence. A Project field changes only after its issue receives the required
public, issue-specific evidence record. Codex performed the original audit in
the repository owner's working session on 2026-08-28 and reviewed the
terminal-revocation and archive-materialization updates on 2026-08-29. Exact
publishing-revision evidence and class-by-class Required/N/A results are
recorded on every changed issue during live reconciliation, as required by
[the policy](MATURITY.md#recording-a-maturity-change).

The #27 archive comparison handles one archive per CLI invocation and satisfies
its bounded acceptance at the exact public revision above. Its successful
report remains non-mutating and evidence-only: it establishes neither current
signer custody nor signing or recovery authority. It is classified
**Prototype complete** and **Met**. The #29 implementation separately provides
direct activation with exact pins, a current-key custody challenge, an atomic
sealed receipt, retained source evidence, signer-free exact replay,
authenticated post-activation binding history, and fully guarded
operational-head reads. Its bounded issue acceptance is also classified
**Prototype complete** and **Met**. These are prototype claims, not hardening,
external-review, or production-readiness claims. Recovery activation and
terminal hydration remain at Design.

| Issue | Track | Audited Status | Acceptance evidence | Public evidence and next unmet gate |
| --- | --- | --- | --- | --- |
| [#1 Trusted two-key rotation](https://github.com/SurreptitiousFabric/a-quo/issues/1) | Core identity | **Prototype complete** (was Implementing) | **Met** (was Defined) | The public implementation adds trusted Linux two-key consent, authoritative-journal statement construction, dual signing, full-chain verification, atomic key handoff, and exact committed-proof retry to the [portable protocol](CONTINUITY.md), with rejection, cancellation, stale-state, substitution, fork, rollback, crash, and retry tests. This bounded prototype result does not claim independent security review, packaging, accessibility, or production readiness. |
| [#2 Continuity and audit hardening](https://github.com/SurreptitiousFabric/a-quo/issues/2) | Core identity | **Implementing** (was Prototype complete) | Defined | Continuity supports independently supplied root, latest-policy, and exact head checkpoints; deterministic attack matrices cover prefixes, forks, omissions, duplicates, reordering, cross-persona splices, partial journal rewrites, and backup-event mutations. The operational prototype records an append-only pinned recovery-policy chain and atomically commits successor recovery or an explicitly capability-authorized terminal no-successor leaf. The terminal path preserves v1 replacement-only authority, uses policy statement v2 opt-in, commits zero active keys plus signer unbinding and immutable evidence under schema v8, returns the first wrapper on exact replay, and preserves the leaf in quarantined backup v3. The public #27 comparison adds non-mutating independent comparison without authority; #29 adds schema-v9 immutable materialization provenance, exact direct projection, current-tip custody, rollback, and replay checks. Multi-candidate handling, recovery activation, terminal hydration, existing-live fork resolution, trusted multi-party recovery/terminal consent, external witnessing, sustained fuzzing and broader leak analysis, product UX, and independent external security review remain open. |
| [#3 Root distribution and recovery UX](https://github.com/SurreptitiousFabric/a-quo/issues/3) | Core identity | Design | Defined | [Continuity](CONTINUITY.md) and [recovery](KEY-RECOVERY.md) define pins and non-claims; interoperable distribution and tested restoration UX remain undesigned. |
| [#4 Threshold recovery](https://github.com/SurreptitiousFabric/a-quo/issues/4) | Core identity | Prototype complete | Defined | The [recovery protocol](KEY-RECOVERY.md), [core integration tests](../crates/a-quo-core/tests/recovery_round_trip.rs), and [CLI flow](../crates/a-quo-cli/tests/recovery_flow.rs) meet the issue's original ten successor-recovery prototype gates. Policy statement v2 and terminal threshold authority expand the hardening scope tracked under #2; they do not silently redefine the already frozen #4 acceptance matrix. Five explicit ceremony, hardening, UX, and review gates remain open. |
| [#5 Maturity gates](https://github.com/SurreptitiousFabric/a-quo/issues/5) | Core identity | **Done** (was Design) | **Met** (was Needs definition) | This policy, this issue-by-issue audit, the [contribution guide](../CONTRIBUTING.md), issue form, and pull-request template satisfy the documentation-only outcome. Independent security review is not applicable; the policy governs review rather than a runtime boundary. |
| [#6 Consent accessibility](https://github.com/SurreptitiousFabric/a-quo/issues/6) | Omarchy | Backlog | Defined | The [threat model](THREAT-MODEL.md) explicitly identifies the missing screen-reader path. A reviewed accessible authority design and real assistive-technology evidence remain absent. |
| [#7 Safe Omarchy packaging](https://github.com/SurreptitiousFabric/a-quo/issues/7) | Omarchy | Design | Defined | [Daemon](DAEMON.md) and [consent IPC](CONSENT-IPC.md) specify trusted paths and per-user isolation. Installable package artifacts and clean-system lifecycle tests do not exist. |
| [#8 Plugin permissions and runtime risk](https://github.com/SurreptitiousFabric/a-quo/issues/8) | Omarchy | Backlog | Defined | [Archive inspection](OMARCHY.md) lists executables and says runtime safety is not evaluated. A versioned risk vocabulary, static findings, and update-expansion consent remain absent. |
| [#9 Omarchy install/update hardening](https://github.com/SurreptitiousFabric/a-quo/issues/9) | Omarchy | **Implementing** (was Prototype complete) | Defined | The [install/update prototype](OMARCHY.md) has bounded hostile-archive parsing, staging, atomic exchange, and rollback tests in [`a-quo-omarchy`](../crates/a-quo-omarchy/). The issue's crash/power-loss, real-corpus, permission, and external-review gates remain unmet. |
| [#10 Real plugin corpus](https://github.com/SurreptitiousFabric/a-quo/issues/10) | Omarchy | Backlog | Defined | Package constraints are documented in [Omarchy integration](OMARCHY.md), but no versioned public corpus or clean-system compatibility matrix exists. |
| [#11 Reproducible builds](https://github.com/SurreptitiousFabric/a-quo/issues/11) | Software supply chain | Backlog | Defined | The pinned [CI workflow](../.github/workflows/ci.yml) builds and tests one environment; independent rebuild comparison and normalized artifact evidence are absent. |
| [#12 Sigstore release publication](https://github.com/SurreptitiousFabric/a-quo/issues/12) | Software supply chain | Backlog | Defined | A Quo can [verify Sigstore bundles](SUPPLY-CHAIN.md), but its workflow publishes no release artifacts, bundles, provenance, or offline consumer evidence. |
| [#13 Build-provenance policy](https://github.com/SurreptitiousFabric/a-quo/issues/13) | Software supply chain | Design | Defined | The [SLSA reporter](SUPPLY-CHAIN.md) deliberately assigns no level and identifies the missing builder/source/build-type/external-parameter expectation policy. |
| [#14 Sigstore verifier hardening](https://github.com/SurreptitiousFabric/a-quo/issues/14) | Software supply chain | **Implementing** (was Prototype complete) | Defined | The isolated [offline verifier](SUPPLY-CHAIN.md) and [integration flow](../crates/a-quo-cli/tests/supply_chain_flow.rs) provide a bounded prototype. The hardening issue still lacks its full adversarial corpus, syscall policy, interoperability matrix, fuzzing, and external review. |
| [#15 TUF update metadata](https://github.com/SurreptitiousFabric/a-quo/issues/15) | Software supply chain | Backlog | Defined | [Omarchy integration](OMARCHY.md) names trusted freshness and rollback metadata as missing; no roles, thresholds, delegation, or update client design exists. |
| [#16 Consented C2PA signing](https://github.com/SurreptitiousFabric/a-quo/issues/16) | Media | Backlog | Defined | A Quo only [verifies embedded C2PA](C2PA.md). Certificate/signing policy, trusted mutation consent, re-verification, and sidecar fallback remain absent. |
| [#17 C2PA verifier hardening](https://github.com/SurreptitiousFabric/a-quo/issues/17) | Media | **Implementing** (was Prototype complete) | Defined | The isolated [offline C2PA verifier](C2PA.md) and [media flow](../crates/a-quo-cli/tests/media_flow.rs) provide a bounded prototype. The hardening outcome still lacks its hostile corpus, seccomp policy, broader formats, fuzzing, and external review. |
| [#18 CAWG identity](https://github.com/SurreptitiousFabric/a-quo/issues/18) | Media | Backlog | Defined | [C2PA reporting](C2PA.md) explicitly leaves CAWG identity unestablished; profile selection, trust inputs, fixtures, and interoperability evidence remain absent. |
| [#19 C2PA certificate trust](https://github.com/SurreptitiousFabric/a-quo/issues/19) | Media | Design | Defined | [C2PA reporting](C2PA.md) separates content binding from certificate trust and revocation. Trust-store, path-building, time, and revocation policy remain to be chosen and tested. |
| [#20 swiyu hand-off](https://github.com/SurreptitiousFabric/a-quo/issues/20) | External identity | Backlog | Defined | The [roadmap](ROADMAP.md) preserves official-wallet custody. No current swiyu protocol profile, request model, wallet interop, or disclosure transcript exists. |
| [#21 DID/blockchain adapters](https://github.com/SurreptitiousFabric/a-quo/issues/21) | External identity | Design | Defined | The [architecture](ARCHITECTURE.md) requires optional connectors and persona separation. Supported methods, resolver trust, chain finality, privacy, and fixtures remain open. |
| [#22 macOS adapter](https://github.com/SurreptitiousFabric/a-quo/issues/22) | Platforms | Backlog | Defined | The portable [architecture](ARCHITECTURE.md) separates platform adapters; no native macOS consent, keystore, packaging, or threat design exists. |
| [#23 Windows adapter](https://github.com/SurreptitiousFabric/a-quo/issues/23) | Platforms | Backlog | Defined | The portable [architecture](ARCHITECTURE.md) separates platform adapters; no native Windows consent, keystore, packaging, or threat design exists. |
| [#24 EU wallet hand-off](https://github.com/SurreptitiousFabric/a-quo/issues/24) | External identity | Backlog | Defined | The [roadmap](ROADMAP.md) preserves EUDI-wallet custody. No selected protocol profile, request object, wallet interop, selective-disclosure test, or revocation report exists. |
| [#25 Portable Linux release](https://github.com/SurreptitiousFabric/a-quo/issues/25) | Platforms | Design | Defined | The Rust workspace, pinned toolchain, [CI](../.github/workflows/ci.yml), and [architecture](ARCHITECTURE.md) are portable foundations. Distribution support, package formats, lifecycle tests, SBOM, signed artifacts, and support policy remain open. |
| [#26 Safe archive-to-live staging](https://github.com/SurreptitiousFabric/a-quo/issues/26) | Core identity | **Implementing** (was Design) | Defined | The staged protocol distinguishes independent comparison from three explicit state-changing modes and forbids longest-chain selection, silent metadata promotion, source-archive deletion, and live-journal overwrite. The public #27 comparison and #29 direct-activation slices cover one exact candidate, including immutable source retention, transactional projection, a sealed receipt, exact retry, and a bounded CLI flow. Recovery activation, terminal hydration, multi-candidate/existing-live fork resolution, CLI/product and contention hardening, and independent review remain pending. |
| [#27 Quarantined archive comparison](https://github.com/SurreptitiousFabric/a-quo/issues/27) | Core identity | **Prototype complete** (was Implementing) | **Met** (was Defined) | Exact public revision `57be5e25096070c667c7891a946ce4e3e2a4bef4` adds typed root/effective-head/policy expectations and `persona backup-compare` for one fully reverified archive per invocation. It derives sequence digests during that bounded verification pass, hashes only the typed archive with RFC 8785 canonical JSON, reports all four required head relations, and treats a terminal v3 leaf as the effective head. Store and CLI tests cover routine, mixed-recovery, terminal, malformed/wrong pins, every relation, canonical-hash scope, tampering, and missing or ambiguous options; every success remains evidence-only/quarantined with custody and authority false. Hosted check, audit, and fuzz evidence is linked above. This satisfies the frozen one-candidate prototype outcome. Multi-candidate UX and every state-changing mode remain separate #26 work. |
| [#28 Terminal archive hydration](https://github.com/SurreptitiousFabric/a-quo/issues/28) | Core identity | Design | Defined | The mode is specified to accept only an exactly pinned terminal v3 history and produce frozen, inspectable state with no active key, signer reference, or authority. No materialization command, transactional projection, immutable receipt, retry/concurrency implementation, or test evidence exists yet. |
| [#29 Direct archive activation](https://github.com/SurreptitiousFabric/a-quo/issues/29) | Core identity | **Prototype complete** (was Design) | **Met** (was Defined) | Exact public revision `57be5e25096070c667c7891a946ce4e3e2a4bef4` requires archive/root/head/policy/current-key expectations, derives the nonterminal tip from fully reverified evidence, proves fresh custody through an explicitly selected signer, retains the immutable source, and atomically seals the exact live projection. Success evidence includes the public CLI import/activation path followed by artifact signing and verification. Tamper and hostile-boundary tests cover every receipt/pin/projection field, metadata and key collisions, signer mismatch/unavailability/replacement, authenticated post-rebind suffixes, clock/policy behavior, and operational-head bypasses. Failure evidence covers every transaction stage, signer-free exact retry, changed-request conflict before signer I/O, concurrent calls, and real pre-/post-commit process aborts. Hosted check, audit, and fuzz evidence is linked above. This satisfies the bounded #29 prototype outcome. Sustained fuzzing/contention, product and platform hardening, trusted consent, independent security review, and production readiness remain explicitly outside that claim. |
| [#30 Recovery archive activation](https://github.com/SurreptitiousFabric/a-quo/issues/30) | Core identity | Design | Defined | The mode is specified to extend an exact nonterminal archive through one threshold-authorized recovery transition and fresh successor custody without briefly authorizing the lost archived key. No activation command, archive-plus-recovery transaction, immutable receipt, retry/concurrency implementation, or test evidence exists yet. |

## Reconciliation required by this audit

The original audit required and received these public Project field changes:

- `#1`: Implementing → Prototype complete and Defined → Met;
- `#2`: Prototype complete → Implementing;
- `#5`: Design → Done and Needs definition → Met;
- `#9`: Prototype complete → Implementing;
- `#14`: Prototype complete → Implementing; and
- `#17`: Prototype complete → Implementing; and
- `#26`: Design → Implementing.

The exact public evidence and dated issue records produced these additional
public Project field changes:

- `#27`: Implementing → Prototype complete and Defined → Met; and
- `#29`: Design → Prototype complete and Defined → Met.

All other Status and Acceptance-evidence values are supported at the audited
revision. Priority, Track, and Dependency values are orthogonal and remain
unchanged.

Rows #26 through #30 distinguish a bounded prototype result from the broader
staging outcome. #27 and #29 now have an exact public revision and hosted CI;
their issue-specific evidence records authorize the live maturity-field
advances. #28 and #30 remain Design/Defined.

Each changed issue must receive a dated public evidence record naming the
auditor, exact publishing commit, previous and new field values, the four
common evidence classes or reviewed N/A rationale, applicable boundary
evidence, remaining gates, and non-claims. That per-issue record—not this table
alone—authorizes the live field mutation.

The remaining work around
[#1 trusted two-key rotation](https://github.com/SurreptitiousFabric/a-quo/issues/1)
belongs to separate hardening, accessibility, packaging, migration, and
recovery outcomes. Hosted CI claims in this audit apply only to their cited
exact revisions; independent security review, later hardening gates, and
production readiness remain incomplete.
