# Documentation authority and structure

This document defines where A Quo statements belong. It is an editing map,
not a product-security claim. Moving prose does not change implementation
behavior, maturity, or evidence strength.

## Document classes

Every maintained document has one primary role:

| Class | Purpose | May contain | Must not become |
| --- | --- | --- | --- |
| Product entry point | Explain the product model, central supported journey, concise commands, and current boundary | Short summaries and links to authoritative contracts | A second protocol manual or chronological run log |
| Normative contract | Define one protocol, invariant set, trust boundary, or operational contract | Stable requirements, formats, algorithms, failure behavior, and residual risks | A diary of commits, CI runs, or superseded checkpoints |
| Planning | State current dependencies, priorities, and unresolved gates | Current status and links to issues/contracts | Historical implementation narrative |
| Maturity summary | Map bounded claims to public evidence and the next unmet gate | Concise issue-by-issue claim/evidence links | A chronological transcript |
| Evidence index | Retain dated commits, workflow runs, artifacts, digests, and historical checkpoints | Exact immutable evidence coordinates and their bounded meaning | Normative policy or a claim that old evidence is current |
| Fixture ledger | Define immutable test or evaluation inputs | Exact externally pinned revisions and digests required to reproduce a corpus | General product status |

## Authoritative homes

| Subject | Authoritative document | Other documents should do this |
| --- | --- | --- |
| Product model, central user journey, concise commands, current bounded status | [README](../README.md) | Link to the README or the narrower contract |
| Component ownership and trust-boundary topology | [Architecture](ARCHITECTURE.md) | Summarize only when needed to orient a reader |
| Adversaries, system-wide security properties, and residual risks | [Threat model](THREAT-MODEL.md) | Link instead of copying the complete limitation list |
| Proof envelope and parser rules | [Proof format](PROOF-FORMAT.md) | Link to the format |
| Persona separation and key-history meaning | [Personas](PERSONAS.md) | Preserve the no-universal-identity rule and link here |
| Portable continuity wire semantics | [Continuity](CONTINUITY.md) | Link to the protocol |
| Backup, materialization, and threshold-recovery operations | [Key recovery](KEY-RECOVERY.md) | Link to the operation-specific contract |
| Persona-root cards and verifier-owned pins | [Root distribution](ROOT-DISTRIBUTION.md) | Link to the trust-basis definitions |
| Daemon responsibility and runtime lifecycle | [Daemon](DAEMON.md) | Link to the daemon contract |
| Approval request fields and decisions | [Approval protocol](APPROVAL-PROTOCOL.md) | Link to the closed prompt format |
| Linux consent transport and the no-D-Bus authority rule | [Consent IPC](CONSENT-IPC.md) | State the rule briefly, then link here |
| Omarchy package inspection and lifecycle semantics | [Omarchy](OMARCHY.md) | Link to the lifecycle contract |
| Omarchy lifecycle implementation ownership and failure map | [Lifecycle module map](OMARCHY-LIFECYCLE-MODULES.md) | Use for code review; keep product semantics in `OMARCHY.md` |
| Package layout, target profiles, evaluator gates, and release handoff | [Packaging](PACKAGING.md) | Keep only concise commands and current status elsewhere |
| Behavioural evidence and the signed-does-not-mean-safe boundary | [Plugin risk](PLUGIN-RISK.md) | Link here rather than duplicating scanner policy |
| Frozen Omarchy corpus inputs | [Omarchy corpus](OMARCHY-CORPUS.md) | Keep exact corpus pins here because they are current fixture identity, not project chronology |
| Accessibility requirements for trusted consent | [Accessibility](ACCESSIBILITY.md) | Link to the test and release gates |
| DNS control semantics | [Domain control](DOMAIN-CONTROL.md) | Link to the claim/nonclaim contract |
| C2PA verification semantics | [C2PA](C2PA.md) | Link to the verifier boundary |
| Sigstore/SLSA verification semantics | [Supply chain](SUPPLY-CHAIN.md) | Link to the verifier boundary |
| Maturity definitions and evidence requirements | [Maturity policy](MATURITY.md) | Never redefine status terms locally |
| Current issue-by-issue claim/evidence summary | [Maturity audit](MATURITY-AUDIT.md) | Link to rows instead of restating the board |
| Current dependencies, priorities, and unresolved work | [Roadmap](ROADMAP.md) | Keep dated execution history out |
| Dated implementation and hosted-run coordinates | [Evidence index](EVIDENCE.md) | Link to a stable evidence record |
| Repository merge and acceptance process | [Repository governance](REPOSITORY-GOVERNANCE.md) | Link to the governance boundary |
| Contributor entry point and submission requirements | [Contributing](../CONTRIBUTING.md) | Link to the relevant normative contract for technical details |
| Supported versions and private vulnerability reporting | [Security policy](../SECURITY.md) | Keep exploit details and sensitive material out of public evidence |

## Pre-refactor duplication inventory

Issue #45 began with the following repeated or misplaced material. This ledger
records the intended destination before compression:

| Repeated or misplaced material | Locations before issue #45 | Authoritative result |
| --- | --- | --- |
| A valid signature establishes bytes and a key, not safety, truth, review, or legal identity | README status and security sections; `OMARCHY.md`; `PLUGIN-RISK.md`; `PACKAGING.md`; `SUPPLY-CHAIN.md`; `C2PA.md` | System-wide boundary in `THREAT-MODEL.md`; domain-specific consequences remain in the relevant contract; README keeps one prominent warning |
| Signing/consent authority stays outside Omarchy and D-Bus | README; `ARCHITECTURE.md`; `ACCESSIBILITY.md`; `DAEMON.md`; `CONSENT-IPC.md`; `PACKAGING.md` | Transport and authority rule in `CONSENT-IPC.md`; architecture and accessibility documents retain only their subject-specific consequences |
| Personas are separate and no universal correlation identifier exists | README; `ARCHITECTURE.md`; `PERSONAS.md`; `THREAT-MODEL.md` | Persona semantics in `PERSONAS.md`; system privacy consequence in `THREAT-MODEL.md`; README keeps the product-level statement |
| Package/evaluator capability lists and never-run qualifications | README status and development sections; `PACKAGING.md`; `ROADMAP.md`; `MATURITY-AUDIT.md` | Normative gates in `PACKAGING.md`; current maturity in `MATURITY-AUDIT.md`; README and roadmap link to them |
| Exact-input lock mechanics and per-class nonclaims | README development section; `PACKAGING.md`; `ROADMAP.md`; `MATURITY-AUDIT.md` | Current commands and class contracts in `PACKAGING.md`; compact status elsewhere |
| Hosted x86 observation, stage-4, and stage-5 run chronology | README; `PACKAGING.md`; `ROADMAP.md` | Exact runs, artifacts, commits, and digests in `EVIDENCE.md`; current x86 policy and gates remain in `PACKAGING.md` |
| Archive materialization and root-distribution publishing revisions and CI runs | `MATURITY-AUDIT.md`; `ROADMAP.md` | Exact chronology in `EVIDENCE.md`; issue-level claims and next gates remain in `MATURITY-AUDIT.md` |
| Joined-lifecycle fixture and input-lock publishing checkpoints | README; `PACKAGING.md`; `ROADMAP.md` | Exact immutable coordinates in `EVIDENCE.md`; current verification commands and external-pin requirements remain in `PACKAGING.md` |
| Maturity and release-readiness disclaimers | README; nearly every normative document; `ROADMAP.md`; `MATURITY-AUDIT.md` | Status semantics in `MATURITY.md`; each normative document retains only the residual risks specific to its own boundary |

## Editing rules

1. Put a new invariant in one normative document and link to it elsewhere.
2. Put run IDs, artifact IDs, publishing commits, and superseded checkpoints in
   `EVIDENCE.md` or the relevant GitHub issue record.
3. Keep an exact revision or digest in a normative document only when a current
   parser, command, fixture, lock, or policy requires that literal value.
4. Do not replace an unknown, untested, or unauthenticated state with positive
   prose while shortening a document.
5. Keep residual risks next to the contract that creates them. A link may
   replace a duplicate, but it must lead directly to the authoritative subject.
6. Treat issue and Project status as separate under `MATURITY.md`.
7. Run `mise run documentation` and `mise run check` after changing maintained
   Markdown.
