# Maturity and acceptance evidence

This document defines the normative maturity language for the
[Witness Me!](https://github.com/users/SurreptitiousFabric/projects/9) A Quo
0.x Project. A card's `Status` describes the maturity of the outcome stated by
that issue. It does not inherit the maturity of an underlying component.

For example, a working verifier may justify “Prototype complete” for the issue
that created it. A later issue whose outcome is to harden that verifier starts
at Backlog, Design, or Implementing until the hardening outcome itself meets a
gate.

## Independent Project fields

The Project fields answer different questions and must not be collapsed:

- **Status** — how mature is this issue's stated outcome?
- **Priority** — how urgently should A Quo pursue it?
- **Dependency** — is progress blocked by no dependency, an internal
  dependency, or an external dependency?
- **Acceptance evidence** — are the issue's complete acceptance requirements
  missing, defined, or all met?

`Acceptance evidence` has these values:

- `Needs definition`: the issue does not yet say what observable evidence
  would establish completion.
- `Defined`: the issue has testable acceptance criteria and names the required
  evidence, but at least one completion criterion remains unmet or lacks
  current, linked evidence.
- `Met`: every completion criterion has current, public evidence linked from
  the issue. An assertion or checked box without supporting evidence is not
  enough.

An issue can therefore be `Prototype complete` with acceptance evidence
`Defined` when it explicitly separates satisfied prototype criteria from later
hardening, review, or release gates. `Done` always requires `Met`.

Prototype scope and the division between prototype and later gates are frozen
at Design exit. They cannot be relabelled afterward merely to advance a card.
A material scope or gate change must be recorded publicly and returns the item
to Design for a new evidence plan.

## GitHub issue state is not Project maturity

The GitHub issue's open/closed state answers whether work remains inside that
issue's frozen outcome. It is not another spelling of the Project `Status`.

A bounded implementation issue may close at `Prototype complete` only when:

- its acceptance evidence is `Met` and the exact public evidence is linked;
- every criterion inside its frozen prototype outcome is satisfied;
- the closure comment says that Project status remains `Prototype complete`
  and repeats the relevant nonclaims; and
- every known hardening, usability, packaging, independent-review, or release
  gate outside that outcome is linked to a separate open issue or explicitly
  recorded backlog item.

Such closure means “the issue's bounded prototype outcome is finished.” It
does not mean the component is `Done`, production-ready, supported, or
independently reviewed. A security-critical card cannot move to Project
`Done` without the applicable external-review gate, whether its original
prototype issue is open or closed.

Keep an issue open when its acceptance evidence is only `Defined`, a checklist
item inside its stated outcome remains unmet, or later work has not been split
into an accountable issue. Umbrella and release issues normally remain open
through their stated release gates. Reopen a closed prototype issue when its
bounded evidence regresses or newly discovered work is actually inside its
frozen scope; do not reopen it merely because a separate hardening issue has
started.

## Status gates

Statuses are normally sequential. Moving a card forward requires all exit
evidence from the current stage and all entry requirements for the next stage.
The only shortcut is the documented Design-to-Done path for an issue whose
entire outcome is a design or research decision and has no runnable security
boundary.

### Backlog

Entry:

- the issue states a desired outcome and why it belongs in A Quo;
- obvious dependencies and non-claims are recorded; and
- no implementation maturity is implied.

Exit to Design:

- scope and trust boundaries are bounded;
- dependencies and applicable standards are identified;
- acceptance evidence is at least `Defined`; and
- open design questions are explicit rather than hidden in implementation.

### Design

Entry:

- the Backlog exit gate is met; and
- relevant architecture, threat, privacy, and interoperability constraints are
  documented.

Exit to Implementing:

- a reviewable protocol, interface, policy, workflow, or research method is
  chosen;
- abuse cases and failure behavior are specified;
- the test and evidence plan covers the applicable Prototype-complete minimum;
- each evidence class is marked Required or N/A with reviewed rationale;
- the prototype scope and later gates are explicitly frozen; and
- no unresolved design choice would materially change the implementation's
  security boundary.

A work item whose entire outcome is a design or research decision can move
from Design directly to Done once all of its acceptance evidence is `Met`. It
must not use Prototype complete merely because the document is a prototype.

### Implementing

Entry:

- the Design exit gate is met; and
- at least one public implementation artifact or test toward this issue's
  outcome exists on the default branch.

Exit to Prototype complete:

- the bounded end-to-end outcome works at an exact public revision;
- every criterion explicitly labelled as a prototype gate is satisfied;
- the common automated evidence below is present;
- applicable track-specific evidence is present; and
- user and verifier documentation says what the prototype proves, does not
  prove, and still cannot do.

If the Design-exit record does not distinguish prototype criteria from later
gates, all acceptance criteria apply before the issue can leave Implementing.

### Prototype complete

Entry:

- the Implementing exit gate is met with linked evidence; and
- known missing hardening, deployment, usability, review, and external
  dependencies are explicit.

Exit to Hardening:

- the prototype scope is stable enough to attack systematically;
- the hardening plan covers hostile input, rollback/fork/replay, interruption,
  resource exhaustion, platform behavior, and applicable usability risks; and
- failures found so far are resolved or recorded with an owner and severity.

Prototype complete means “the bounded prototype works and fails safely in the
tested model.” It does not mean production-ready, audited, safe software,
legally identified, current, accessible, or suitable for unattended use.

### Hardening

Entry:

- the Prototype-complete gate is still satisfied; and
- systematic hardening evidence is landing against the same defined outcome.

Exit to External review:

- all internal acceptance and release gates are met;
- supported environments and residual risks are documented;
- relevant fuzz, property, race, interruption, migration, and clean-system
  tests are complete or explicitly inapplicable with rationale;
- no unresolved internally known critical or high-severity finding remains;
  and
- an exact review revision and review scope are frozen and public.

### External review

Entry:

- the Hardening exit gate is met; and
- a suitably independent reviewer has accepted the exact scope and revision.

Exit to Done:

- findings are public when safe to disclose;
- required findings are fixed and reverified, or explicitly accepted with
  documented rationale;
- every issue acceptance criterion has current evidence; and
- no dependency required for the stated outcome remains unresolved.

External review is required for security-critical release boundaries. For a
documentation-only issue, the issue must state why independent security review
is not applicable before moving directly to Done.

An external reviewer must be outside the implementation decision chain, state
financial or organizational conflicts, have demonstrated competence in the
reviewed boundary, and control enough time and artifact access to reproduce the
relevant evidence. A product, service, or model calling itself “independent” is
not sufficient evidence. Cryptographic, trusted-consent/key-use, package
activation, and regulated-credential release boundaries require external
review before Done.

### Done

Entry:

- acceptance evidence is `Met`;
- the stated outcome, documentation, applicable tests, applicable
  migration/rollback behavior, and support boundary are complete; and
- the issue links the exact evidence that justified closure.

Done is a current evidence claim, not a permanent badge. Regression rules
still apply.

## Minimum automated evidence for Prototype complete

Runnable implementation work must provide all four evidence classes below at
an exact public revision. Tests must run through the repository's pinned Mise
toolchain locally and in CI unless a documented environment constraint makes
one side impossible. Such a constraint requires substitute immutable public
evidence from the real target environment; documentation alone does not waive
an evidence class.

1. **Success:** an end-to-end test exercises the public interface and verifies
   the resulting security-relevant state or portable output, not merely that a
   helper returned success.
2. **Tamper:** automated tests alter every security-relevant binding appropriate
   to the format, such as bytes, digest, signature, signer, purpose namespace,
   identity, sequence, policy, or metadata, and prove rejection.
3. **Hostile input:** parsers and boundary code test malformed, truncated,
   oversized, duplicated, reordered, unknown-critical, path-confusing, and
   display-confusing inputs as applicable. Limits must be explicit.
4. **Failure path:** tests exercise applicable cancellation, denial, timeout,
   missing dependency, stale state, conflict, partial write, crash/retry,
   rollback, and cleanup behavior. Failure must not silently claim success or
   leave ambiguous authority.

The evidence link must also identify:

- the exact commit;
- the test command and relevant test files or CI run;
- the threat-model and user-documentation changes;
- residual limitations and non-claims; and
- any evidence that is simulated rather than observed on a real platform or
  external implementation.

Passing `mise run check` is necessary for code changes but is not, by itself,
evidence that these four classes are covered.

Applicability is fixed at Design exit in a small matrix covering Success,
Tamper, Hostile input, Failure path, and every relevant boundary subsection
below. Each cell is `Required` or `N/A` with a reviewed, issue-specific reason.
Missing tooling, fixtures, hardware, access, implementation, or time is a gap,
not N/A. If scope changes make an N/A class relevant, the card returns to
Design before it advances again.

## Additional evidence by boundary

Use every subsection that applies to an issue; work spanning multiple
boundaries inherits the union of their requirements.

### Cryptographic and continuity code

- Canonical bytes, algorithm identifiers, domain separation, key roles, and
  verifier inputs are specified.
- Independent verification rejects substitution, cross-purpose reuse,
  downgrade, replay, fork, truncation, and ambiguous encodings as applicable.
- Key compromise, rotation, recovery, expiry, revocation, and historical
  validity are reported separately.
- Test fixtures use real supported cryptographic tooling in addition to unit
  doubles, and an external security review is required before Done.

### Trusted consent and key use

- The trusted display shows the exact human decision and security-relevant
  digest, persona, key roles, purpose, and caller evidence.
- Approval authority stays outside an untrusted caller and outside D-Bus.
- Immutable input, signer selection, post-consent revalidation, cancellation,
  timeout, replay, concurrent requests, and crash/retry behavior are tested.
- Accessibility evidence covers the real trusted surface without adding an
  unreviewed remote approval path.
- External security review is required before a trusted consent or key-use
  authority boundary is Done.

### Packaging, installation, and updates

- Package contents, ownership, permissions, service lifecycle, dependency
  provenance, and supported platforms are explicit.
- Tests cover clean install, upgrade, downgrade refusal, interruption,
  rollback, uninstall, stale state, and hostile package contents.
- Verification, publisher continuity, permission expansion, review, and safety
  remain separate decisions.
- Clean-system testing and external review are required before Done.

### Accessibility

- Every user-facing action, decision, evidence view, and error has a complete
  keyboard path, perceivable focus, understandable name/state/output, and
  usable scaling/contrast.
- Screen-reader or other assistive-technology limitations are observed on the
  real trusted surface, not inferred from toolkit structure.
- An accessibility workaround must not give another process authority to
  approve a security decision.
- Known exclusions identify affected users and block Done for a generally
  available release unless explicitly scoped out of the stated outcome.

### External protocols and wallets

- The exact standard version, conformance profile, external implementation,
  trust registry, and interoperability fixture are recorded.
- Offline mocks establish local logic only; Prototype complete requires an
  end-to-end test with a conforming external implementation or an issue scope
  that explicitly says “simulator prototype.”
- Network, wallet, issuer, holder, verifier, revocation, disclosure, and
  correlation boundaries are reported separately.
- Regulated or policy-bound credentials, including swiyu and EUDI credentials,
  remain in their authorized wallets. Portable credentials and blockchain
  adapters follow their own explicit custody policy. An external service outage
  or policy change cannot be reported as identity revocation.

## Regression and backward movement

Move a card backward as soon as authoritative evidence no longer supports its
current gate. Do not wait for a release or board review.

| Event | Required response |
| --- | --- |
| Required test is failing, disabled, skipped, stale, or no longer covers the shipped path | Move to the highest gate still proven, no higher than Implementing; use Design if the repair changes the boundary. |
| Security assumption, standard, dependency API, acceptance criterion, or platform behavior is invalidated or materially changed | Move to the highest still-proven gate, normally Design until a replacement decision and evidence plan exist. |
| Prototype no longer works end to end at public `main` | Move to the highest still-proven gate below Prototype complete. |
| A critical/high finding invalidates an internal hardening claim | Move to the highest still-proven gate below Hardening; use Design if architecture must change. |
| External reviewer has not reviewed the current security-relevant revision | Move to the highest still-proven gate below External review. |
| A closed issue loses evidence for its bounded outcome, or a required dependency inside that outcome becomes unresolved | Reopen the issue, set evidence to Defined, and move to the highest still-proven status. |
| Prototype scope or the division between prototype and later gates changes materially | Record the change, set evidence to Defined, and move to Design. |
| Only priority, scheduling, or staffing changed | Keep Status; update Priority instead. |
| Only an external service is unavailable and local evidence remains valid | Keep Status; update Dependency and describe the blocked verification. |

## Recording a maturity change

Every forward or backward change must leave a public issue comment or body
update containing:

- previous and new Status;
- previous and new Acceptance evidence value;
- exact commit or immutable external artifact;
- links to success, tamper, hostile-input, and failure-path evidence, or a clear
  explanation of why a class does not apply;
- applicable track-specific evidence;
- remaining gates and non-claims; and
- who performed the audit and its date.

The [contribution guide](../CONTRIBUTING.md), issue form, and pull-request
template apply this rule to future work. The current board audit is recorded in
[A Quo 0.x maturity audit](MATURITY-AUDIT.md).
