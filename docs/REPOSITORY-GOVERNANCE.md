# Repository governance

This policy defines how changes enter A Quo's default branch. It exists to
make security-sensitive changes reviewable; it is not product-security
evidence and does not make a change correct merely because the process passed.

## Default merge path

All ordinary changes enter `main` through a focused pull request associated
with one bounded issue outcome. Direct pushes, force pushes, and deletion of
the default branch are prohibited by repository protection. Pull requests use
linear history and resolve review conversations before merge.

The protected branch requires these exact checks from `.github/workflows/ci.yml`:

- `check` — the repository-required Mise task and locked dependency audit;
- `fuzz` — the bounded fuzz campaigns and fuzz-workspace audit;
- `portable root distribution (ubuntu-24.04)`;
- `portable root distribution (macos-15)`; and
- `portable root distribution (windows-2025)`.

Required checks must pass on the exact pull-request head. A workflow name or
job-name change must update the protection rule in the same reviewed change,
without an interval in which an obsolete or missing check is silently treated
as success.

## Acceptance and review provenance

Every security-sensitive pull request records separately:

1. who or what produced the implementation;
2. who or what designed the tests and where independent fixtures came from;
3. what automation established on the exact revision;
4. the repository owner's acceptance judgement after those results; and
5. any independent reviewer required by the issue's maturity gate.

The owner acceptance record is a pull-request review or comment made after the
required results are available. It states the bounded outcome, evidence used,
remaining unknowns, and nonclaims. It must not describe self-generated tests
as independent review. For a solo-owned repository, GitHub cannot manufacture
independence: an owner reviewing their own change remains owner acceptance,
not external review.

The branch rule therefore requires the pull-request path and automated checks
but does not require an approving review count that the sole author is unable
to satisfy. Issues whose maturity gate requires independent review remain open
until a genuinely separate reviewer accepts the exact scope and revision.

## Reviewable changes

A pull request should change one security boundary or one behavior-preserving
refactor at a time. Literal evidence, generated data, mechanical movement, and
behavioral logic should be separated when combining them would obscure the
review. Large changes need an invariant map and decomposition rationale before
implementation; green CI is not a substitute for that explanation.

A refactor must name a measurable reviewability improvement. Its pull request
records the relevant before-and-after measurement instead of relying on a
general claim that the code is cleaner. Suitable measures include:

| Before | Required direction after |
| --- | --- |
| Very large files | Smaller, purpose-specific modules |
| Repeated functions | One shared mechanism |
| Stringly typed states | Enums and structured results |
| Many overlapping concepts | Fewer public concepts |
| Long control flow | Clear state transitions |
| Duplicate test construction | Shared fixtures or independent black-box tests |
| Repeated documentation disclaimers | One authoritative boundary statement |

Movement alone is not success. Each refactor must preserve the applicable
behavior and hostile-path checks, state which metric improved, and explain any
metric that did not improve or became worse.

Review must identify:

- the invariant or outcome being changed;
- the hostile and failure paths affected;
- the authoritative test or independent oracle, if one exists;
- serialized or compatibility consequences;
- rollback or recovery behavior; and
- the claims that remain unestablished.

## Emergency procedure

Repository administrators can technically alter or bypass repository
settings. That capability is not an ordinary merge path. An emergency bypass
is limited to an actively exploited vulnerability or a failure that prevents
the required workflow from evaluating any pull request.

Before bypass, when disclosure is safe, open or identify an issue that records
the reason, exact intended change, owner, and rollback. Make the smallest
change possible, restore the protection rule immediately, and follow with a
pull request that exposes the exact diff and all applicable checks. If public
detail would expose a sensitive vulnerability, use a private GitHub security
advisory and publish a sanitized record when safe.

An administrator's ability to edit the protection rule remains a platform
limitation. It must never be reported as cryptographic, independent, or
tamper-proof enforcement.
