# Omarchy plugin risk-evidence integration

Status: **corrected candidate design; Stage-0 A Quo record
shape/binding prototype implemented; Plug & Prejudice pre-install integration
and product policy gate not implemented**

This document defines the boundary between A Quo and
[Plug & Prejudice](https://github.com/SurreptitiousFabric/plug-and-prejudice)
for Omarchy plugin installation and updates.

The central rule is simple:

> A behavioural reviewer determines what a plugin appears capable of doing. A
> Quo determines which exact signed package that evidence belongs to, who
> supplied it, what changed, what local policy requires, and whether the user
> should be asked before the same bytes are installed.

A Quo does not parse plugin source to rediscover commands, network use,
filesystem access, persistence, privilege requests, or other behaviour. It
does not maintain a second generic behavioural evidence language. The first
integration consumes and retains one supported Plug & Prejudice native report.
Plug & Prejudice is the first and best-supported reviewer, not an inseparable
part of A Quo core. A universal behavioural/capability ontology remains out of
scope. Core has only a minimal behaviour-blind registry for approved adapter
and component identity.

Today A Quo can verify a package and proof, inspect a bounded archive, and
report structural facts. Its `omarchy_manifest_validation` and
`runtime_safety` results remain `not_run` and `not_evaluated` where that work
has not happened. See [Omarchy integration](OMARCHY.md),
[the package contract](PACKAGING.md), and [maturity](MATURITY.md).

## Signed and analysed do not mean safe

A signature can establish which key signed exact package bytes. Persona
evidence can establish continuity from a root a verifier already accepts. A
scanner report can establish what one identified scanner reported about one
identified input under its documented methods and limitations.

None of those facts establishes that a plugin is harmless.

A Quo keeps the questions separate:

| Dimension | Example answer | What it does not answer |
| --- | --- | --- |
| Artifact | These are the package bytes whose SHA-256 digest is `...` | Who should be trusted |
| Publisher | This accepted persona/key signed those bytes | Whether the code is safe |
| Package structure | The archive contains these files and no links | What the files will do |
| Behavioural analysis | Plug & Prejudice reported these facts, inferences, unknowns, and limitations | Whether every runtime path was found |
| Review | A named reviewer examined one exact snapshot | Whether later bytes are equivalent |
| Local policy | This evidence requires a block or fresh consent | Whether damage is impossible |

Unknown, unsupported, incomplete, and error are first-class outcomes. A local
policy may block on one of them, but neither A Quo nor its UI may silently
relabel an absent finding as a clean result. The product reports several
evidence dimensions rather than one green “trusted” or “safe” indicator.

## Responsibility boundary

### Plug & Prejudice owns behavioural analysis

Plug & Prejudice owns:

- parsing shell, QML, Python, JavaScript, binaries, manifests, and other plugin
  content for behavioural meaning;
- identifying commands, filesystem and network resources, privilege and
  persistence behaviour, desktop/session effects, and dynamic or native-code
  limitations;
- facts, inferences, unknowns, evidence chains, severity, confidence,
  analysis coverage, limitations, and scanner errors;
- scanner rules and correlations;
- containment, no-execution and no-network guarantees, resource limits, and
  scanner failure handling; and
- tests of obfuscation, unsupported syntax, false positives, false negatives,
  parser coverage, and behavioural detection.

Its versioned native report is the authoritative behavioural report. A Quo
does not translate that report into a second full graph of capabilities,
observations, evidence, coverage, limitations, and errors.

### A Quo owns the operation around that analysis

A Quo owns:

- verifying the package signature and publisher/persona continuity;
- validating the archive as an installable object, including paths, entry
  types, counts, sizes, manifest identity, and exact package digest;
- constructing the exact bounded pre-install snapshot supplied to the
  scanner;
- retaining the native report byte for byte and binding its digest to that
  exact snapshot and signed package;
- identifying the exact trusted Plug & Prejudice broker, scanner, report
  schema, ruleset, and A Quo adapter involved in the operation;
- retaining the adapter-validated opaque native-report binding and status;
- applying local policy to reviewer availability, status, and an
  adapter-derived provider-specific comparison without reparsing plugin source;
- keeping publisher, structural, scanner, review, and policy evidence
  separate;
- obtaining trusted, single-use consent; and
- installing or updating from the same verified package descriptor that was
  assessed.

A Quo and Plug & Prejudice may both record a fact such as “this archive
contains an executable file,” but for different purposes. A Quo needs that
fact to unpack and install safely and faithfully. Plug & Prejudice decides what
the executable may imply about plugin behaviour. Structural installation
validation is not a second behavioural scan.

Neither process receives signing keys. Plug & Prejudice never runs in the A
Quo signing daemon and never gains consent or installation authority. A Quo's
install/update coordinator is a separate unprivileged component with no
signing authority. The interface is private descriptor passing, not D-Bus, a
public socket, or a network service.

## Useful without a behavioural reviewer

A Quo core does not require Plug & Prejudice in order to verify artifact and
publisher signatures, validate package structure, calculate file/version/
publisher deltas, stage a plugin disabled, preserve the prior version, or roll
back a failed activation.

Without a supported reviewer adapter, behavioural analysis is explicitly
`not_run` or unavailable. That is never shown as “no risks found,” “clean,” or
safe. Local policy either blocks the operation or requires a trusted prompt
that clearly warns the user that plugin behaviour was not analysed.

This permits a useful minimal A Quo installation while keeping the security
loss visible. It also means a Plug & Prejudice packaging or compatibility
failure does not corrupt identity, signature, structure, staging, or rollback
evidence.

## Same owner is not independent review

Plug & Prejudice and A Quo currently share the SurreptitiousFabric owner.
Separate repositories, binaries, privileges, reports, and release boundaries
still improve containment and make the scanner independently usable. They do
not make its output an organizationally independent security review.

A Quo must display the report as **Plug & Prejudice-attributed evidence**, not
as external certification or A Quo truth. Independent review remains a
separate evidence dimension.

## Exact pre-install flow

The scanner-side work is tracked in
[Plug & Prejudice #31](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/31).
That issue fixes the deliberately narrow first transport:
`a-quo-regular-file-stream-v1` in a sealed `memfd` inherited by the private
Plug & Prejudice broker.

```text
A Quo verifies one signed package descriptor
        |
        v
A Quo performs bounded archive/manifest validation
        |
        v
A Quo creates one canonical regular-file stream in a sealed memfd
        |
        v
Plug & Prejudice validates that descriptor and materializes it only inside
its private containment
        |
        v
Plug & Prejudice scans without executing plugin content and emits its native
report for the bytes it observed
        |
        v
the Plug & Prejudice-specific adapter validates the native report and exact
subject and derives bounded provider-specific display/comparison data
        |
        v
A Quo retains the opaque native report binding, verifies component identity
and status, compares package/publisher/structure evidence, and applies policy
        |
        v
trusted prompt ---> same sealed assessment ---> install/update the same
verified package descriptor
```

The subject is never a mutable installed pathname. An installed-directory
report cannot be substituted for the approved pre-install snapshot. A changed
package, stream, report, scanner, ruleset, destination, policy, or deadline
invalidates the operation.

Until Plug & Prejudice #31, the provider-specific adapter, and the matching A
Quo core binding are implemented and reviewed, no repository document or UI
may claim pre-install behavioural analysis.

## Exact regular-file stream

The proposed `a-quo-regular-file-stream-v1` representation is one binary byte
stream. Multi-byte integers are unsigned and big-endian. There is no padding.

The 20-byte header is:

| Bytes | Meaning |
| --- | --- |
| 8 | literal ASCII magic `AQRFSV1` followed by one NUL byte |
| 4 | regular-file count |
| 8 | sum of all file-content lengths |

Exactly `file_count` records follow. Each record is:

| Bytes | Meaning |
| --- | --- |
| 4 | UTF-8 path length |
| 4 | normalized mode: integer 420 (`0644`) or 493 (`0755`) |
| 8 | content length |
| 32 | raw SHA-256 digest of the content |
| `path_length` | path bytes |
| `content_length` | exact file-content bytes |

Records are sorted by unsigned bytewise comparison of their path bytes. Paths
are non-empty, valid UTF-8, NFC-normalized, relative POSIX paths using `/`, and
contain no empty, `.` or `..` component, leading slash, trailing slash, NUL,
backslash, control character, bidi control, or default-ignorable character.
Duplicate paths are invalid. The executable bit is normalized to `0755`; every
other accepted regular file is `0644`.

Owner, timestamps, extended attributes, ACLs, devices, explicit directories,
links, and other archive metadata do not appear. Directories are implied by
file paths. `manifest.json`, when present, is an ordinary record containing
its exact accepted bytes.

The header's count and content total must equal the records, every record
digest must match its content, and the stream must end immediately after the
last content byte. Candidate bounds are 4,096 records, 4,096 bytes per path,
128 MiB per file, 512 MiB total file content, and 600 MiB for the complete
framed stream. `manifest.json` is additionally capped at 64 KiB by A Quo's
archive validator. A mismatch, trailing byte, or non-regular entry fails
stream construction.

The planned A Quo coordinator writes the stream to a new anonymous memfd,
verifies it from the beginning, and applies `F_SEAL_WRITE`, `F_SEAL_GROW`,
`F_SEAL_SHRINK`, and
`F_SEAL_SEAL` before launch. Plug & Prejudice #31 independently validates the
descriptor type, seals, offset, framing, bounds, order, per-file digests, and
immediate EOF before scanning. It materializes files only inside its existing
private no-network, no-execution, resource-bounded containment.

The coordinator must retain the same immutable package descriptor from proof
verification through stream construction, report binding, assessment, and
action. It rehashes the package and stream after the scanner returns and before
sealing the assessment. The action rehashes the same descriptors before
mutation and installs from that package descriptor, never from a later
pathname lookup.

This duplicate validation is intentional at the transport boundary: both
processes verify the bytes they consume. It does not duplicate behavioural
analysis.

## A Quo structural evidence

A Quo's structural record describes only facts needed to validate and install
the package safely:

- exact package digest, size, and format;
- exact accepted manifest bytes and parsed plugin identity/version;
- normalized file paths, modes, sizes, and content digests;
- archive entry counts and rejected link/special-entry counts;
- entry-point and executable inventory; and
- exact regular-file-stream digest and length.

It rejects traversal, absolute and duplicate paths, links, devices and other
special entries, excessive counts and sizes, invalid manifests, unsafe display
text, and subject mismatches. It does not infer what a command will execute,
where a plugin may connect, what a script means, or whether an executable is
malicious. Those are Plug & Prejudice concerns.

## Native report retention and binding

Provider-specific schema parsing belongs in a separately packaged adapter. The
provisional first package name is `a-quo-provider-plug-and-prejudice`; that name
is not yet a release promise. The adapter validates one explicitly supported
Plug & Prejudice native report schema and derives only Plug & Prejudice-specific
display and comparison data.

A Quo core does not parse arbitrary provider JSON or create a provider-neutral
copy of behavioural semantics. It retains the unchanged native bytes plus the
closed opaque `NativeReportBinding`: `provider_id`, native schema/digest/size,
and integration status. The adapter cannot grant installation authority,
rewrite local policy, or discard the original report.

For each operation, A Quo must retain:

- the exact native report bytes and their SHA-256 digest and length;
- the supported native report schema and scanner-reported version;
- the exact package and regular-file-stream digest and length;
- the exact manifest identity/digest established by A Quo;
- the Plug & Prejudice broker, scanner, and ruleset/policy identities and
  component digests established from trusted installed files;
- the containment and run status actually established by the broker; and
- any explicit unsupported, incomplete, error, timeout, or resource-limit
  state.

A Quo calculates the package and stream digests itself. The trusted adapter
requires the native report to name the same observed subject, and core binds
that adapter result and native-report digest to its own subject. A report's own
subject label is not authority. A report for a mutable installed copy, a
different stream, an old package, or a caller-supplied label is rejected.

The original report remains available for bounded inspection. The adapter may
derive a small, versioned provider-specific policy/display projection, but that
projection must be deterministic and reproducible from the retained report.
It must not become an A Quo evidence graph or silently change Plug &
Prejudice's fact, inference, unknown, limitation, or error meanings.

All native-report and adapter-display strings are hostile input. The adapter
bounds its parsed output, and A Quo displays it as plain text without treating
it as QML, HTML, Markdown, terminal escapes, URLs to open, shell, or paths with
authority.

Malformed, oversized, unsupported, contradictory, stale, wrong-subject, or
substituted reports fail closed. Scanner launch or containment failure, timeout,
partial output, invalid output, and resource exhaustion are explicit error or
unavailable states, never empty clean reports.

## Scanner identity and provenance

A self-declared scanner name or version inside JSON is not sufficient. The
planned coordinator opens the installed Plug & Prejudice
adapter/broker/scanner/ruleset components without following links, verifies root
ownership and non-writable path constraints, and hashes the descriptors that
will actually execute or be consumed.

The root-owned `/usr/share/a-quo/provider-registry-v1.json` is the minimal
generic execution/identity seam. Core initially ships it empty and therefore
works with no behavioural reviewer. A reviewed Plug & Prejudice installation,
potentially through the provisional `a-quo-provider-plug-and-prejudice`
package, supplies a closed entry through the reviewed package-composition path
that identifies:

- one `provider_id` used by the opaque `NativeReportBinding`;
- the approved adapter, broker, scanner, and ruleset components and their exact
  digests;
- the expected native report schema; and
- the fixed isolation/execution profile needed to invoke those components.

The registry contains no capabilities, findings, evidence graph, coverage
translation, risk score, local-policy rule, display prose, or install decision.
It authorizes which exact local component bytes may participate; it does not
interpret their behavioural report.

A future real reviewer can add its own adapter/component entry and native
schema without changing A Quo core's opaque binding type. Its adapter still
owns all provider-specific parsing and comparison. This narrow replaceability
seam is not permission to restore the removed universal behavioural ontology.

Component identity establishes which local bytes participated. It does not
establish that those bytes, their owner, their findings, or their build are
trustworthy. Signed releases, SBOMs, reproducibility evidence, and independent
review remain separate supply-chain evidence.

## Update comparison

An update is a new subject, so an old report cannot be carried over as current
analysis. A Quo retains old and new native reports. Their provider-specific
adapter compares them only when the report schema, scanner semantics, and
ruleset identity are compatible under an explicitly reviewed comparison rule.

The behavioural meaning of commands, resources, facts, inferences, unknowns,
coverage, and limitations remains defined by Plug & Prejudice. Its adapter
either:

1. consumes a stable Plug & Prejudice-owned comparison/summary contract; or
2. derives a minimal deterministic Plug & Prejudice-specific policy projection
   from two supported native reports.

It never obtains the delta by parsing plugin source itself.

New or broadened behaviour, a new unknown, reduced analysis coverage, a new
limitation/error, a changed scanner or ruleset, or incompatible report versions
is material. Local policy may block or require fresh informed consent. It may
not call an incomparable or reduced-coverage result unchanged or safe.

A Quo separately compares package identity and digest, manifest ID/version,
publisher persona and key continuity, file additions/removals/content/mode
changes, and whether every report belongs to the exact previous or current
subject.

## Additional reviewers and disagreements

A real second behavioural reviewer may be added later through its own
provider-specific adapter and reviewed package boundary. Core continues to
retain each unchanged native report under a distinct `provider_id`, digest,
and status; it does not require both reviewers to share one behavioural schema.

If two reviewers disagree, A Quo attributes and displays their separate
results, methods, unknowns, and limitations. It never averages severity,
confidence, or findings into a safety score and never lets one “clean” report
erase another report's finding or unavailable state. Local policy may block or
require warned consent based on either result or on the disagreement itself.

## Local policy

The policy is local data, not scanner output and not a script supplied by the
plugin. Its inputs remain separate:

- publisher authorization and continuity;
- manifest and structural-package validity;
- Plug & Prejudice availability, identity, run status, unknowns, limitations,
  and errors;
- a compatible behavioural comparison or explicit indeterminate state;
- review evidence, when separately available; and
- operation, destination, and update facts.

The current Stage-0 policy result permits only `block` or
`require_consent`. It has no `allow`, `safe`, or single green trust verdict.
The future product may refine policy only after the native-report consumer and
trusted prompt are implemented and reviewed.

Policy cannot rewrite Plug & Prejudice claims. It decides what A Quo will do
when presented with them.

## Operation-local assessment and consent

The planned assessment is local to one install or update attempt. It binds:

- a cryptographically random, non-zero operation ID;
- install or update action;
- exact package and stream subject;
- destination and retained destination-parent identity;
- publisher and structural evidence digests;
- retained Plug & Prejudice native-report digest and scanner identity;
- exact old/new comparison inputs where applicable;
- local policy and policy-result digests; and
- issue and expiry times with a monotonic deadline.

The coordinator writes the assessment once to a sealed memfd. The trusted
prompt receives the same sealed assessment and referenced descriptors and
shows the action, destination, publisher/continuity evidence, structural facts,
Plug & Prejudice attribution and status, relevant findings/unknowns/
limitations/errors, update changes, and local-policy result. Its decision
binds the operation ID and assessment digest.

Before mutation, the action path rechecks the assessment digest, operation ID,
one-time state, action, destination, retained safe parent descriptor, package,
stream, publisher evidence, structural record, native report, scanner identity,
comparison, policy, result, and deadline. It installs from the same verified
package descriptor. Consent is consumed by one attempted action. Retry, expiry,
or any changed input requires a new scan, assessment, and prompt as applicable.

The prompt is a new typed approval subject, not the current artifact-signing
prompt with caller-generated prose. Caller text cannot select a scanner,
suppress a finding, downgrade an unknown, construct a policy result, or
control prompt semantics. Command-line text, `--yes`, and the prototype's
separate `--accept-behavioral-analysis-not-run` acknowledgement are not
substitutes for trusted consent. See [the accessibility
contract](ACCESSIBILITY.md).

Saved assessments are not portable security attestations or historical proof.
They require reassessment before use.

## What the current Stage-0 prototype does

The current `a-quo-omarchy::risk` module, the
[candidate JSON Schemas](../schemas/omarchy-plugin-risk-v1/), and the
[fictional golden update](../fixtures/omarchy-plugin-risk-v1/) implement closed
candidate records for:

- publisher evidence;
- structural evidence;
- update file/version/publisher deltas;
- local policy;
- policy result; and
- an operation assessment.

The parsers enforce bounded exact JCS, reject unknown/missing/malformed fields,
unsafe display text, invalid normalized paths and identifiers, unsafe integers,
excessive nesting, oversized records, wrong subjects, inconsistent file
deltas, bad publisher-continuity claims, and cross-record digest substitutions.
The golden update blocks because scanner evidence cannot yet be compared.

This is useful exact-subject, structure, policy, and binding work. It is not a
scanner, native Plug & Prejudice report parser, scanner-provenance check,
pre-install adapter, policy eligibility decision, trusted prompt, or installer
connection.

The Stage-0 core surface is now narrowed to opaque native-report attachments
and integration status. The former generic capability keys,
observations, evidence entries, coverage deltas, limitation/error identifiers,
and capability-policy rules have been removed. A Quo does not interpret native
report behaviour at this stage. The remaining candidate records are not yet
advertised as v1: concrete Plug & Prejudice report validation, exact
pre-install subject binding, scanner provenance, and compatible comparison
still require implementation and review. No compatibility promise is made for
the current candidate schemas.

The public helper remains deliberately named
`validate_risk_record_set_shape_and_bindings`: it checks record shape and
non-circular bindings, not scanner truth or package eligibility.

## Acceptance stages

No stage may claim success by depending on the result it is meant to
establish.

### Stage 0: correct and freeze the A Quo binding contract (#8)

- retain publisher, structural, exact-subject, file/version, policy-result,
  and assessment invariants from the prototype;
- freeze the narrowed opaque native-report attachment around the concrete
  Plug & Prejudice adapter contract;
- freeze the minimal behaviour-blind adapter/component identity registry and
  its empty-core form;
- define scanner component provenance and failure states;
- publish machine-readable schemas, bounds, golden vectors, negative tests,
  and sustained parser fuzz evidence; and
- review the operation-assessment threat decision.

**Current status: Design / Defined.** The existing shape/binding prototype is
not a frozen v1 contract.

### Stage 1: immutable package/proof corpus (#10)

Freeze canonical packages, proofs, manifests, update pairs, and A Quo-owned
hostile archive/lifecycle variants under
[the Layer 1 corpus criteria](OMARCHY-CORPUS.md). Behavioural analyzer corpus
expectations belong to Plug & Prejudice.

### Stage 2: sealed pre-install scanner integration (#8 and Plug & Prejudice #31)

Implement and review the sealed regular-file stream on both sides. Plug &
Prejudice validates, contains, scans, and emits its native report. The
provider-specific adapter validates that report and derives only its bounded
display/comparison projection. A Quo core retains and binds the opaque report,
verifies component identity and status, applies local policy, and tests
malformed, unsupported, stale, substituted, wrong-subject, incomplete, and
changed-scanner results.

### Stage 3: trusted product integration (#6/#7/#9)

Implement the operation-local assessment, local policy, single-use deadline
binding, accessible trusted prompt, and same-snapshot install/update handoff.
Clean-system tests cover consent, installation, update, rollback,
interruption, stale assessment rejection, and preservation of the prior
working version.

Release acceptance additionally requires hostile-input testing, fuzzing,
keyboard and assistive-technology checks, proportionate independent security
review of both repositories' boundaries, and native package evidence.

## Deliberate non-claims

This integration does not establish:

- absence of malware or vulnerabilities;
- behaviour of every runtime path;
- safety of remote services, future downloads, or post-install updates;
- truthfulness of comments, manifests, scanner output, or publisher claims;
- legal identity, copyright ownership, code review, or current authorization;
- organizational independence of Plug & Prejudice;
- freshness or portability of an unsigned operation-local assessment; or
- that the scanner, A Quo, their packages, policies, or UI are defect free.

Runtime containment, least privilege, review, reputation, revocation,
rollback, and incident response remain separate controls. A signature proves
only what its verification and subject binding establish. Analysis proves only
what the named Plug & Prejudice version, exact input, declared methods, and
reported limitations support.
