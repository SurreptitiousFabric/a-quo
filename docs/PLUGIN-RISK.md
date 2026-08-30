# Omarchy plugin risk evidence

Status: **candidate v1 design; Stage-0 referenced-record shape/binding
prototype implemented; schema freeze incomplete; no scanner or policy gate**

This document proposes the first bounded interface for attaching
provider-attributed risk evidence to exact Omarchy plugin bytes. The formats
below are candidates for schema freeze. Closed Rust parsers, machine-readable
schemas, and one synthetic blocked/indeterminate golden update now exist for
the five formerly undefined referenced records and the operation assessment.
They validate record shape, canonical bytes, internal invariants, and a bounded
set of non-circular cross-record bindings. They do not provide a scanner,
provider registry or envelope parser, install coordinator, trusted risk prompt,
eligibility decision, or active policy gate.

Today A Quo can verify a package and proof, inspect a bounded archive, and
report structural facts. Its `omarchy_manifest_validation` and
`runtime_safety` results remain `not_run` and `not_evaluated` where that work
has not happened. See [Omarchy integration](OMARCHY.md),
[the package contract](PACKAGING.md), and [maturity](MATURITY.md).

## The rule: signed does not mean safe

A signature can establish which key signed exact package bytes. Persona
evidence can establish continuity from a root a verifier already accepts.
Neither fact establishes that a plugin is harmless.

A Quo must keep several questions separate:

| Dimension | Example answer | What it does not answer |
| --- | --- | --- |
| Artifact | These are the bytes whose SHA-256 digest is `...` | Who should be trusted |
| Publisher | This accepted persona/key signed those bytes | Whether the code is safe |
| Package structure | The archive contains an executable and no links | What the executable will do |
| Risk analysis | A named provider observed an outbound-network API | Whether every execution path was found |
| Review | A named reviewer examined one exact snapshot | Whether later bytes are equivalent |
| Install policy | This evidence satisfies one local policy | Whether damage is impossible |

Unknown, unsupported, incomplete, and error are first-class outcomes. A local
policy may decide that an unknown blocks installation, but neither an adapter
nor the UI may silently relabel it as safe. A Quo reports a vector of evidence,
not one green “trusted” result.

## Terms and responsibility boundary

In this document:

- **package snapshot** means the immutable package bytes already verified by
  A Quo;
- **analysis stream** means the deterministic regular-file representation
  derived from that snapshot;
- **provider** means one registry-authorized source of analysis evidence;
- **native report** means the provider-specific bytes emitted by a provider;
- **evidence envelope** means A Quo's closed translation of one provider run;
- **assessment** means an operation-local collection of envelopes, structural
  facts, update deltas, and one local policy result; and
- **capability** means a conservatively normalized operation/resource claim
  that policy and update comparison may consume.

In the full design, A Quo owns package binding, the analysis-stream format,
the provider registry, the common envelope, conservative capability
translation, update comparison, local policy, and trusted presentation. The
implemented Stage-0 Rust boundary owns only the referenced-record parsers,
canonical encoders, shape checks, and non-circular digest/binding checks. A
provider owns its scanner, rules, native report, coverage claims,
observations, and limitations.

Provider prose is untrusted input. A Quo retains the native-report digest and
attributes every translated result to the registered components that produced
it. It does not silently reinterpret a provider's result as an A Quo fact.

Providers receive no signing keys and never run inside the A Quo signing
daemon. The planned install/update coordinator is a separate, unprivileged
component with no signing authority. It will invoke executable providers in a
bounded, no-network worker using private file descriptors rather than D-Bus or
a public local service.

## Plug & Prejudice

[Plug & Prejudice](https://github.com/SurreptitiousFabric/plug-and-prejudice)
is the intended first optional deep-analysis provider. It and A Quo have the
same SurreptitiousFabric owner. It is therefore **operationally separate**, not
organizationally independent.

The published revision
[`56dcee89f024c40e4244e6ea35c2fdb1fd40411a`](https://github.com/SurreptitiousFabric/plug-and-prejudice/commit/56dcee89f024c40e4244e6ea35c2fdb1fd40411a)
defines a bounded Go scanner/broker/report contract, but its v1 workflow
analyses installed plugin directories. It does not implement the pre-install,
exact-snapshot adapter specified here.

Consequently:

- the adapter and its registry entry are planned, not implemented;
- its native and translated results remain Plug & Prejudice-attributed
  evidence, not A Quo truth;
- an unavailable, invalid, wrong-snapshot, or incomplete result is never a
  clean result;
- the A Quo signing daemon never invokes it; and
- no uncommitted Plug & Prejudice worktree state is part of this baseline.

It may later be a specialised recursion/corpus subject, but it is not one of
the three representative ordinary plugins required by the initial
[Omarchy corpus](OMARCHY-CORPUS.md).

## Candidate analysis flow

```text
sealed verified package snapshot
        |
        v
bounded safe extraction
        |
        v
sealed a-quo-regular-file-stream-v1 memfd
        |                         |
        |                         +--> built-in structural evidence
        v
registry-selected isolated provider adapter
        |
        v
provider-native report bytes
        |
        v
closed validation and canonical evidence envelope
        |
        v
single-use sealed operation assessment
        |
        v
future trusted prompt ---> same assessment ---> install/update action
```

The subject is never a mutable installed pathname. Safe extraction retains the
path, entry-type, count, and size constraints in
[Omarchy integration](OMARCHY.md). A provider cannot substitute an installed
copy, follow a link outside the snapshot, or fetch code from the network.

## Exact analysis-stream candidate

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
| 4 | normalized mode: integer 420 (`0644`, bytes `00 00 01 a4`) or 493 (`0755`, bytes `00 00 01 ed`) |
| 8 | content length |
| 32 | raw SHA-256 digest of the content |
| `path_length` | path bytes |
| `content_length` | exact file-content bytes |

Records are sorted by unsigned bytewise comparison of their path bytes. Paths
are non-empty, valid UTF-8, NFC-normalized, relative POSIX paths using `/`, and
contain no empty, `.` or `..` component, leading slash, trailing slash, NUL,
backslash, control character, bidi control, or default-ignorable character.
Duplicate paths are invalid. The executable bit is normalized to `0755`; every
other accepted regular file is `0644`. Owner, timestamps, extended attributes,
ACLs, devices, directories, links, and other archive metadata do not appear.
Directories are implied by file paths. `manifest.json`, when present, is an
ordinary record containing its exact accepted bytes.

The header's count and content total must equal the records, every record
digest must match its content, and the stream must end immediately after the
last content byte. Candidate bounds are 4,096 records, 4,096 bytes per path,
128 MiB per file, 512 MiB total file content, and 600 MiB for the complete
framed stream. `manifest.json` is additionally capped at 64 KiB by the
archive validator. Accepted explicit directory entries are validated and then
omitted because directories are implied by file paths. A mismatch, trailing
byte, or any other non-regular entry fails stream construction.

The coordinator writes the stream to a new anonymous memfd, verifies it from
the beginning, and applies `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`, and
`F_SEAL_SEAL` before launch. Only that sealed descriptor and bounded metadata
cross the worker boundary. No package or plugin pathname is authoritative.
The provider may create a private sandbox copy for a tool that needs files,
but its report remains bound to the SHA-256 digest and exact length of the
sealed stream.

The coordinator retains the same immutable package descriptor from proof
verification through stream construction, provider runs, assessment, and the
eventual action. It rehashes the package and analysis-stream descriptors after
provider completion and immediately before sealing the assessment; the action
rehashes the same descriptors again before mutation and installs from that
package descriptor, never from a later pathname lookup. Any mismatch aborts
and discards the operation.

This representation replaces the former undefined “extracted-tree digest.” No
implementation may invent a host-dependent directory hash and label it v1.

## Root-owned provider registry

The candidate registry path is the package-reserved
`/usr/share/a-quo/provider-registry-v1.json`. It is a regular `root:root` file
with mode `0644`; it, its parent directories, and every listed component must
be non-symlink, root-owned, and not group- or world-writable. Provider
components are package files at `/usr/bin/a-quo` or beneath the A Quo-owned
`/usr/lib/a-quo` prefix.

The registry is UTF-8 JSON whose raw bytes equal its RFC 8785 JCS serialization
byte for byte. It contains exactly:

```text
schema       literal "urn:a-quo:omarchy-plugin-risk-provider-registry:v1"
providers    ordered array of provider entries
```

Each provider entry contains exactly:

```text
provider_id
provider_version
analysis_kind
isolation_profile
native_report_schema
runner_component_role
components
```

`runner_component_role` is `builtin` or `adapter`. `components` has one to
four entries, each containing exactly:

```text
role          builtin | adapter | scanner | ruleset
path          /usr/bin/a-quo or a normalized absolute path beneath /usr/lib/a-quo
sha256        lowercase digest of the installed regular-file bytes
```

Roles are unique and ordered `builtin`, `adapter`, `scanner`, `ruleset` after
omitting absent roles. The runner role must exist. Registry provider IDs are
unique and sorted bytewise. Provider IDs, analysis kinds, and isolation
profiles use the 64-byte identifier grammar below. Provider versions are 1 to
128 visible ASCII bytes matching `[0-9A-Za-z][0-9A-Za-z.+_-]*`.
`native_report_schema` is 1 to 256 visible ASCII bytes with no whitespace.
Component paths use at most 4,096 UTF-8 bytes. Unknown fields and enum values
are invalid.

The coordinator, never the plugin or provider process, selects an entry, opens
the registry and every component without following links, validates the open
descriptors' ownership, type, and modes, and hashes those same descriptors. It
executes the runner from its verified descriptor (for example, with Linux
`execveat(..., AT_EMPTY_PATH)`) and supplies verified scanner and ruleset
descriptors to the adapter. It never hashes a pathname and then reopens that
pathname for execution. A built-in re-execution likewise verifies the current
`/proc/self/exe` descriptor rather than assuming the installed pathname still
names the running bytes. Registry authorization identifies which local bytes
were allowed to run. It does not establish that those bytes, their owner, or
their findings are trustworthy or safe.

The registry and component paths are reserved by
[the package contract](PACKAGING.md), but no active registry loader or provider
launcher exists yet.

## Canonical provider evidence envelope

Each provider run produces one UTF-8 JSON object whose raw bytes must equal its
RFC 8785 JSON Canonicalization Scheme (JCS) serialization byte for byte. A BOM,
leading or trailing whitespace, duplicate key, invalid UTF-8, non-canonical
number, unknown field, or unknown enum value is invalid. Numeric fields are
non-negative integers; floating-point and exponent forms are not used.

The top-level object contains exactly, in semantic terms:

```text
schema
subject
provider
run
coverage
capabilities
observations
evidence
limitations
errors
```

`schema` is the literal
`urn:a-quo:omarchy-plugin-risk-evidence:v1`. Object member order on the wire is
JCS order, not the explanatory order in this document.

### `subject`

The subject object contains exactly:

```text
artifact_sha256          lowercase SHA-256 of the sealed package bytes
artifact_size            exact package byte length
package_format           initially "omarchy-zstd-tar-v1"
plugin_id                validated manifest identifier, or null
plugin_version           validated manifest version, or null
manifest_sha256          exact manifest-byte digest, or null
analysis_stream_schema   literal "a-quo-regular-file-stream-v1"
analysis_stream_sha256   SHA-256 of the entire sealed analysis stream
analysis_stream_size     exact stream byte length
```

Artifact fields must equal A Quo's verified immutable package snapshot.
Analysis fields must equal the sealed memfd. Null manifest fields mean that no
valid value was established; caller labels and installed copies cannot fill
them.

### `provider`

The provider object contains exactly:

```text
registry_sha256
provider_id
provider_version
analysis_kind
isolation_profile
native_report_schema
components
```

Each component contains exactly `role`, `registered_sha256`, and
`observed_sha256`. The registered value comes from the selected registry;
the observed value is the coordinator's digest of the installed component, or
null when it could not be read. Entries use registry role order.

`native_report_schema` is copied from the selected registry entry and is the
expected schema. In a native-report descriptor, `schema` is the observed
schema string or null when bounded decoding could not establish one. A
`complete`, `incomplete`, or `unsupported` run with a native report requires
an exact schema match. A different or missing observed schema produces a
`decode` error, not a provider-selected change of identity.

A `complete`, `incomplete`, `unsupported`, or `not_run` envelope is valid only
when every observed digest is present and equals its registered digest. A
missing or different component produces only an `error` run at the `registry`
stage. This prevents a no-run or failed run from claiming that named bytes
actually ran.

### Tagged `run` variants

`run` is one of five closed tagged objects. `native_report` is an object with
exactly `schema`, `sha256`, and `size`; `schema` is a bounded string or null,
and its digest covers raw provider bytes.

```text
complete:
  status             literal "complete"
  native_report      required native-report object

incomplete:
  status             literal "incomplete"
  native_report      required native-report object
  limitation_ids     non-empty sorted list of limitation IDs

error:
  status             literal "error"
  stage              registry | snapshot | launch | analysis | timeout |
                     resource_limit | decode | translate | bind
  code               bounded machine-readable identifier
  native_report      native-report object or null

unsupported:
  status             literal "unsupported"
  reason_code        bounded machine-readable identifier
  native_report      native-report object or null

not_run:
  status             literal "not_run"
  reason_code        bounded machine-readable identifier
```

No other fields are allowed. Only the coordinator may synthesize `not_run`.
`complete` means the provider completed the coverage it claims; it does not
mean exhaustive, finding-free, reviewed, or safe.

For `complete`, `incomplete`, `unsupported`, and `not_run`, `errors` is empty.
For `error`, `errors` is non-empty and contains an entry matching the tagged
stage and code. Every ID in `limitation_ids` resolves to `limitations`.

The remaining content is status-specific:

- `not_run` has all eight coverage entries `not_assessed` with empty reference
  lists, and empty capabilities, observations, evidence, limitations, and
  errors;
- `unsupported` has all eight coverage entries `unsupported` with empty
  reference lists, and empty capabilities, observations, evidence,
  limitations, and errors;
- `error` has all eight coverage entries `error`, each referencing at least
  one top-level error matching the run stage/code, and has empty capabilities,
  observations, evidence, and limitations; and
- only `complete` and `incomplete` may carry capability or observation claims.

A registry-stage provider envelope is possible only after the registry itself
was canonical and a unique valid provider entry was selected. It records a
missing, unsafe, or digest-mismatched component from that entry. Gross registry
parse failure, ambiguous/missing provider selection, or unsafe registry-path
ownership is a coordinator/assessment failure and cannot be attributed by
inventing a provider envelope. Every error stage other than `registry` requires
all observed component digests to be present and matched.

### `coverage`

Coverage contains exactly one entry for each category, in this order:

1. `filesystem`
2. `network`
3. `process`
4. `privilege`
5. `desktop_session`
6. `update_and_install`
7. `persistence`
8. `native_or_dynamic_code`

Each entry contains exactly `category`, `status`, `method`, `summary`,
`limitation_ids`, and `error_ids`. `status` is `assessed`, `partial`,
`not_assessed`, `unsupported`, or `error`; `method` is a bounded
machine-readable provider method ID or null; `summary` is bounded untrusted
plain text; and both ID lists are sorted and unique. Omission is invalid.
`not_assessed`, `unsupported`, and `error` never mean “none observed.” The
built-in structural provider may report archive facts, but must mark
unanalysed behaviour `not_assessed`.

Within a `complete` or `incomplete` run, coverage `error` is invalid;
`assessed` has empty limitation/error lists, while `partial`, `not_assessed`,
and `unsupported` have at least one limitation ID and no error ID. Coverage
`error` is reserved for the all-eight entries of a tagged `error` run. The
closed whole-envelope rules above define the deliberately empty lists for
`not_run` and whole-input `unsupported`. Every non-empty ID resolves to the
corresponding top-level array.

### Closed `capabilities`

Capabilities are the only provider claims that local policy and update-delta
logic consume directly. Narrative observations cannot grant, suppress, or
expand them. Each capability contains exactly:

```text
id
category
operation
resource_kind
resource_value
scope
basis
confidence
evidence_ids
```

`basis` is `fact`, `inference`, or `unknown`. `confidence` is `high`, `medium`,
`low`, or `unknown`. `evidence_ids` is sorted and unique. An unknown claim uses
the category's `unknown` operation, `unknown` resource kind, null value,
`unknown` scope, basis, and confidence.

Every capability ID is referenced by at least one observation. A `fact` or
`inference` capability has at least one immutable evidence ID; an `unknown`
capability may have none, but cannot be relabelled as a fact merely because a
provider supplied confident prose.

The comparison key `(category, operation, scope, resource_kind,
resource_value)` is unique within one envelope. Two differently named
capabilities with the same comparison key are invalid rather than counted
twice or given ambiguous update semantics.

The operation vocabulary is closed by category:

| Category | Allowed operations in addition to `unknown` |
| --- | --- |
| `filesystem` | `read`, `enumerate`, `create`, `write`, `delete`, `execute` |
| `network` | `resolve`, `connect`, `listen` |
| `process` | `spawn_exact`, `spawn_dynamic`, `signal` |
| `privilege` | `elevate`, `change_identity`, `use_capability` |
| `desktop_session` | `read_ipc`, `write_ipc`, `observe_input`, `inject_input`, `overlay`, `modify_config` |
| `update_and_install` | `download`, `install`, `migrate`, `self_update`, `uninstall` |
| `persistence` | `autostart`, `service`, `timer` |
| `native_or_dynamic_code` | `load_native`, `dynamic_import`, `evaluate`, `download_execute` |

`resource_kind` is `path_exact`, `path_prefix`, `host_exact`, `domain_suffix`,
`cidr`, `port_range`, `command_exact`, `ipc_name`, `service_name`,
`config_key`, `capability_name`, or `unknown`. `scope` is `package`,
`plugin_state`, `home`, `system`, `session`, `lan`, `internet`, or `unknown`.

Path resource values are normalized absolute-within-scope POSIX paths. They
begin with exactly one `/`, are NFC UTF-8, and contain no empty, `.` or `..`
component, repeated slash, backslash, NUL, control, bidi-control, or
default-ignorable character. `path_prefix` ends in `/`; `path_exact` does not,
except that `/` may name the scope root. The scope supplies the namespace: for
example, `/manifest.json` under `package` and `/Documents/` under `home` do not
mean the host filesystem root. A `system` path is rooted at the host
filesystem. Commands are absolute host POSIX paths under `system` and obey the
same component rules.

Hosts and domain suffixes are lower-case IDNA ASCII without wildcards. CIDRs
use canonical network/prefix form. Port ranges use `tcp:START-END` or
`udp:START-END`. Other identifiers are lower-case ASCII. Only an `unknown`
resource permits a null value. An adapter must choose `unknown`, not invent a
new operation or resource form.

The non-unknown category/operation/scope/resource combinations are also
closed. This prevents two adapters from encoding the same behavior as
different policy keys, or encoding nonsense such as a network connection to a
home-directory path:

| Category and operation | Allowed scopes | Allowed resource kinds |
| --- | --- | --- |
| `filesystem` and any non-unknown filesystem operation | `package`, `plugin_state`, `home`, `system` | `path_exact`, `path_prefix` |
| `network/resolve` | `lan`, `internet` | `host_exact`, `domain_suffix` |
| `network/connect` | `lan`, `internet` | `host_exact`, `domain_suffix`, `cidr`, `port_range` |
| `network/listen` | `lan`, `internet` | `cidr`, `port_range` |
| `process/spawn_exact` | `system` | `command_exact` |
| `process/spawn_dynamic`, `process/signal` | `session` | `capability_name` |
| `privilege` and any non-unknown privilege operation | `system` | `capability_name` |
| `desktop_session/read_ipc`, `desktop_session/write_ipc` | `session` | `ipc_name` |
| `desktop_session/observe_input`, `desktop_session/inject_input`, `desktop_session/overlay` | `session` | `capability_name` |
| `desktop_session/modify_config` | `home`, `session` | `path_exact`, `path_prefix`, `config_key` |
| `update_and_install/download` | `internet` | `host_exact`, `domain_suffix`, `cidr`, `port_range` |
| Other non-unknown `update_and_install` operations | `plugin_state`, `home`, `system` | `path_exact`, `path_prefix` |
| `persistence/autostart` | `home`, `session` | `path_exact`, `path_prefix`, `config_key` |
| `persistence/service`, `persistence/timer` | `session`, `system` | `service_name` |
| `native_or_dynamic_code/load_native`, `dynamic_import`, `evaluate` | `package`, `plugin_state`, `home`, `system` | `path_exact`, `path_prefix` |
| `native_or_dynamic_code/download_execute` | `internet` | `host_exact`, `domain_suffix`, `cidr`, `port_range` |

The one unknown form is exactly category-specific operation `unknown`, scope
`unknown`, resource kind `unknown`, and a null resource value. A partially
unknown or out-of-matrix key is invalid.

### `observations`

Each observation contains exactly:

```text
id
category
kind             fact | inference | unknown
severity         info | low | medium | high | critical | unknown
confidence       high | medium | low | unknown
title
summary
assumptions
capability_ids
evidence_ids
```

The ID lists are sorted and unique. `fact` has no assumptions. `inference` has
at least one bounded plain-text assumption. `unknown` has unknown confidence
and may name assumptions explaining the gap. Severity is provider metadata,
not an install decision. All prose is untrusted display text, never terminal
escapes, markup, QML, shell, or an automatically opened URL.

Facts and inferences have at least one evidence ID. Unknown observations may
have no source evidence, but cannot be translated into a capability other than
the closed unknown form.

### `evidence`

Each evidence entry contains exactly:

```text
id
source           snapshot_file | analysis_stream | native_report
source_sha256
path
byte_start
byte_length
```

For `snapshot_file`, `path` is a normalized stream path and `source_sha256` is
that file's content digest. For the other sources, `path` is null and the
digest is the exact stream or report digest. The non-empty byte range must be
within the named immutable source.

The envelope contains no provider-supplied excerpt. A future trusted renderer
may derive a bounded escaped excerpt from immutable source bytes. If those
bytes are unavailable, it shows the location and limitation rather than
presenting provider prose as source evidence.

### `limitations` and `errors`

Each limitation contains exactly `id`, `category`, `code`, and `summary`.
`category` is one closed category or null. Each error contains exactly `id`,
`stage`, `code`, and `summary`; its stage is one of the closed error stages in
`run`. Codes are bounded machine-readable identifiers and summaries are
untrusted plain text.

Crash, invalid report, timeout, resource exhaustion, adapter rejection, and
subject mismatch are errors, never an empty clean report.

## Determinism, references, and bounds

IDs match `[a-z0-9][a-z0-9._-]{0,63}` and are unique across capabilities,
observations, evidence, limitations, and errors. All references resolve within
the same envelope.

Before JCS serialization, arrays have these semantic orders:

- coverage uses the fixed category order;
- provider components use the fixed role order;
- capabilities sort by category, operation, scope, resource kind, resource
  value (null first), then ID;
- observations, evidence, limitations, and errors sort by ID; and
- reference-ID lists sort by raw ASCII bytes without duplicates.

A decoder rejects a differently ordered array even if its object-member order
is otherwise canonical.

Candidate v1 bounds are:

| Item | Maximum |
| --- | ---: |
| Canonical provider registry | 1 MiB |
| Registered providers | 16 |
| Canonical envelope | 8 MiB |
| Provider native report | 64 MiB |
| Canonical operation assessment | 1 MiB |
| Capabilities | 4,096 |
| Observations | 4,096 |
| Evidence entries | 16,384 |
| Limitations or errors | 1,024 each |
| Assumptions per observation | 16 |
| References in one list | 64 |
| Identifier | 64 ASCII bytes |
| Resource value, path, title, summary, or assumption | 4,096 UTF-8 bytes |
| JSON nesting depth | 16 |

The worker also needs fixed CPU, memory, process, descriptor, output, and
wall-time limits. Those values belong to a closed `isolation_profile` frozen
with implementation; an adapter cannot attest to its own sandbox. The trusted
UI follows [the accessibility contract](ACCESSIBILITY.md) for hostile text and
full-value review.

## Implemented candidate referenced records

The assessment no longer hashes five undefined objects. The candidate parser
prototype in [`a-quo-omarchy::risk`](../crates/a-quo-omarchy/src/risk.rs), the
[JSON Schemas](../schemas/omarchy-plugin-risk-v1/), and the
[fictional golden update](../fixtures/omarchy-plugin-risk-v1/) define these
closed records:

| Record | Schema | Exact role |
| --- | --- | --- |
| Publisher evidence | `urn:a-quo:omarchy-plugin-publisher-evidence:v1` | Carries an exact subject and proof digest with closed publisher/key/continuity states and internally derived install authority. Stage 0 does not read the proof or authenticate the registry, signature, persona, or key. It contains no free-form trust verdict. |
| Structural evidence | `urn:a-quo:omarchy-plugin-structural-evidence:v1` | Carries normalized regular-file facts and internally checks counts, byte totals, manifest binding, executable/entry-point lists, and the exact analysis-stream length formula. Stage 0 does not construct or parse the stream or derive these facts from package bytes. |
| Update delta | `urn:a-quo:omarchy-plugin-update-delta:v1` | Binds exact old/new subjects and publisher/structure record digests; derives publisher continuity, plugin/version state, exact file changes, and consent flags; and binds nullable previous/current provider-envelope digests. Provider comparability is currently always `unavailable`; capability and coverage comparison claims must be empty. |
| Local policy | `urn:a-quo:omarchy-plugin-local-policy:v1` | Defines closed missing/incomplete/error/unknown/update handling and exact capability-key rules. It is data, not a script or caller expression. |
| Policy result | `urn:a-quo:omarchy-plugin-policy-result:v1` | Binds one preallocated operation ID, action, subject, policy and evidence digests, provider IDs/statuses/digests, ordered reasons, and only `block` or `require_consent`. Stage 0 independently derives only reasons that do not require provider-envelope interpretation. |

The shared subject is the artifact digest/size, package format, manifest
identity/digest, and analysis-stream digest/size. Every subject-bearing
referenced record and the assessment requires a valid non-null manifest
subject. The more general future provider envelope still permits all three
manifest fields to be explicitly null together so a failed analysis can be
attributed without inventing a manifest.

Every nullable wire member is nevertheless required: omission and explicit
`null` are different. Every object rejects unknown fields. The current Rust
parsers bound each raw record at 1 MiB and nesting depth 16; reject invalid
UTF-8, duplicate/unknown members, non-JCS bytes, non-exact integers, unsafe or
non-NFC display text, invalid normalized paths/resources, unordered arrays,
duplicates, and invalid internal state combinations; and expose canonical
encoders and digests. JSON Schema describes the portable shape, but its
annotations make clear that Rust validation remains authoritative for UTF-8
byte limits, RFC 8785 raw-byte equality, Unicode 17 display exclusions,
semantic ordering, containment, and cross-record hashes. Neither parser nor
schema authenticates an artifact, proof, registry, provider envelope, native
report, or analysis stream merely because a record contains a digest or a
`verified`/`complete` tag.

Structural validation requires at most 4,096 entries, regular files, and
explicit directories; at most 128 MiB per file, 512 MiB in total, and 64 KiB
for `manifest.json`; and exactly zero links and special entries. For path byte
lengths and file sizes from the sorted `files` array, it requires:

```text
subject.analysis_stream_size = 20 + sum(48 + path_utf8_bytes + file_size)
```

This catches an internally inconsistent size but does not verify the stream
digest or contents without the still-open binary stream implementation.

The binding order has no hash cycle:

```text
publisher + structure + optional old evidence + provider envelopes
                              |
                              v
                         update delta

local policy + exact evidence + preallocated operation ID
                              |
                              v
                         policy result
                              |
                              v
                  operation assessment digest
                              |
                              v
                   future one-shot consent
```

No input record contains the assessment digest. The policy result precedes and
is hashed by the assessment; a future prompt decision would then bind the
operation ID and final assessment digest. An update requires the exact retained
old publisher and structural records. Reconstructing old evidence from a
mutable installed directory is invalid.

The current public helper is deliberately named
`validate_risk_record_set_shape_and_bindings`. It checks equal subjects,
actions, non-zero operation IDs, canonical record digests, update/install
nullability, old/new evidence presence, exact file deltas, and the assessment-
to-policy-result binding. It derives plugin-ID change by equality and version
change by SemVer precedence: build metadata is ignored, so changing only
`+build` metadata is `equal`, not `upgrade`.

Publisher continuity is `matched` only when both records have the same
non-null, non-nil local persona ID and both say `verified` against the same
non-null persona-root digest. It is `mismatched` when the two non-null IDs
differ, when either same-ID record says `invalid`, or when two same-ID
`verified` records do not carry the same non-null root. Every other
combination is `not_checked`.

Stage 0 has no provider envelope parser or identity projection. Its records
carry provider IDs, run statuses, and previous/current envelope hashes only;
they do not carry provider-version, component, scanner, ruleset, or other
provider identity fields. Every provider delta therefore has
`comparability: "unavailable"`, an empty
`coverage_regressions` array, and an empty `capability_changes` array;
non-empty coverage or capability comparison claims are rejected until the
Stage-2 envelope parser can recompute them. `permission_expansion` is
consequently false. The provider-delta array is the sorted union of retained
old and current provider bindings and is capped at 32 entries: 16 previous
plus 16 current. The delta still binds each nullable
`previous_envelope_sha256` and `current_envelope_sha256` to the same provider
ID in those old and current binding lists, and every binding in either list
must appear in the delta. A provider delta with neither hash, or with a hash
that does not match the corresponding retained binding, is invalid. A provider
delta is material even when both hashes exist, so it makes
`fresh_consent_required` true and produces an `indeterminate_comparison`
reason. Run-status and new limitation/error IDs remain shape-checked and
digest-bound inputs, not independently authenticated provider facts.

The helper derives the mandatory interactive reason; hard publisher,
continuity, manifest, plugin-ID, and version reasons; required-provider and
declared run-status reasons; indeterminate comparison; and declared new
limitation/error reasons. `unknown_capability`, `default_capability`, and
`capability_rule` reasons cannot be derived until provider envelopes are
interpreted. Stage 0 permits those three only with the exact disposition in
the local policy (and an existing rule for `capability_rule`); it does not
establish that the reason should be present. Parsing and cross-record checking
therefore do not authenticate provider output or make an install eligible.

Policy reasons use the exact tuple order `(code, disposition, provider_id,
rule_id)`. Code order is `interactive_approval_required`,
`publisher_not_authorized`, `publisher_continuity_not_matched`,
`manifest_validator_not_passed`, `missing_required_provider`,
`provider_incomplete`, `provider_error`, `provider_unsupported`,
`provider_not_run`, `new_provider_limitation`, `new_provider_error`,
`plugin_id_changed`, `version_not_upgrade`, `permission_expansion`,
`coverage_regression`, `indeterminate_comparison`, `unknown_capability`,
`default_capability`, then `capability_rule`. Disposition order is `block`
before `require_consent`; provider and rule IDs are null first and otherwise
raw-ASCII ordered. Duplicate tuples are invalid. `default_capability` requires
a provider ID and a null rule ID; only `capability_rule` has a non-null rule ID.

The golden vector contains exact canonical old/new publisher and structural
records, an unavailable-comparison provider delta with no permission or
coverage claim, policy, a blocking indeterminate policy result, and assessment.
Its manifest records every raw byte length and SHA-256 and says explicitly that
the fictional records establish neither safety, legal identity, provider
independence, install eligibility, nor production readiness.

## Deterministic update deltas (Stage-2 target)

An update is a new subject, so old analysis cannot be carried over. The
following is the target comparison after Stage 2 freezes provider identity and
parses old/new envelopes. It is not accepted as a Stage-0 comparison claim.
A Quo then compares capability keys `(category, operation, scope,
resource_kind, resource_value)`.

One key covers another only when category, operation, and scope match and
either the resource is equal, a path prefix contains the other path, a domain
suffix contains it on a DNS-label boundary, a CIDR contains it, or a port
range contains it for the same transport. Equal keys are unchanged. If the old
key covers the new key, the new claim is narrower and is not an expansion. If
the new key covers the old key but not vice versa, it is `expanded`. Otherwise
replacement is one `removed` old key plus one `added` new key. A new `unknown`
is material.

A capability may be called removed only when both reports have matching
provider, component, and ruleset identity and that category is `assessed` in
both. Otherwise the result is `indeterminate`. Provider/ruleset change,
coverage regression, or unavailable evidence requires fresh consent;
narrative wording never controls the delta.

The target assessment also reports publisher continuity, plugin ID/version,
downgrade, file/content/mode changes, new limitations/errors, and unavailable
required evidence.

File deltas sort by path. Provider deltas sort by provider ID. Within a
comparable provider, capability changes sort first by change order (`added`,
`expanded`, `removed`), then by null-first previous and current capability
keys. Capability keys use the fixed category and scope/resource-kind orders in
this document, raw-ASCII operation order, and null-first resource values.

## Operation-local assessment, not portable proof

Provider envelopes are canonical and hashed, but v1 does **not** sign them or
claim historical freshness. The planned coordinator authenticates them only
inside one private local operation using inherited descriptors, the root-owned
registry, component digests, and immutable inputs. A saved or reloaded
assessment is untrusted input and requires reassessment.

This section specifies a Stage-3 coordinator requirement, not current product
behavior. The Stage-0 Rust helper checks the assessment's canonical shape and
referenced-record bindings only; it has no sealed-descriptor lifecycle,
provider-envelope authentication, trusted prompt, one-shot state, or action
handoff.

For an install or update, the coordinator creates a JCS object containing
exactly:

```text
schema                 "urn:a-quo:omarchy-plugin-risk-assessment:v1"
operation_id           random 32-byte value as 64 lower-case hex characters
action                 install | update
subject                exact evidence-envelope subject object
destination            normalized absolute installation path
destination_parent_device  retained parent-directory device as lower-case hex
destination_parent_inode   retained parent-directory inode as lower-case hex
registry_sha256        exact registry digest
publisher_evidence_sha256
structural_record_sha256
update_delta_sha256     canonical update delta digest, or null for install
policy_sha256          exact closed local-policy digest
policy_result_sha256   canonical policy-result digest
provider_envelopes     sorted entries of provider_id, envelope_sha256,
                       and complete | incomplete | error | unsupported | not_run
issued_at_unix         wall-clock seconds for display
expires_at_unix        wall-clock expiry seconds
```

`operation_id` comes directly from the operating system CSPRNG. The Stage-0
parser cannot prove randomness from record bytes, but it rejects the reserved
all-zero value. Both time values are non-negative JCS-safe integers no greater
than `2^53 - 1`; `expires_at_unix` is greater than `issued_at_unix` by at most
600 seconds.
Device and inode values are unsigned lower-case hexadecimal with at most 16
digits, without a prefix or leading zero (except the value `0`).
`provider_envelopes` has at most the 16 entries allowed by the selected
registry, is strictly sorted by provider ID, and cannot contain a duplicate. A
bare digest list is deliberately invalid: each digest must say which provider
it represents.

Its raw bytes must equal their JCS serialization. The referenced publisher
evidence, structural record, update delta, policy, policy result, and provider
envelopes are canonical sealed descriptors whose raw-byte digests match the
assessment. Every provider-envelope subject is identical and equals the
assessment subject. The coordinator writes the assessment once to a sealed
memfd and computes its digest. The trusted prompt receives those same
descriptors and shows the action, destination, deadline, subject, publisher
evidence, structural evidence, limitations, unknowns, delta, and policy
result. Its decision binds the operation ID and assessment digest.

The coordinator holds a monotonic deadline as well as the displayed
wall-clock expiry. Before mutation, the action path receives the same sealed
assessment and the same sealed referenced descriptors. It rechecks the
assessment digest, operation ID, one-time state, action, destination, retained
safe parent-directory descriptor and identity, package, registry, publisher
evidence, structural record, delta, policy, policy result, envelopes, and
deadline. It re-resolves the displayed path to the same directory immediately
before use and performs mutation relative to the retained descriptor; it never
approves one directory and later reopens a substituted path. Consent is
consumed by one attempted action. Retry, changed input/destination, expiry, or
second use requires a new assessment and prompt.

Wall-clock fields are not a trusted historical timestamp. Portable signed risk
attestations need a different schema plus signer trust, timestamp, revocation,
and replay policy; they are outside v1.

## Future trusted presentation and policy

The install/update prompt is a new typed approval subject, not the current
artifact-signing prompt with caller-generated prose. It independently derives
and displays the package, publisher/continuity evidence, structural facts,
registry-derived provider identity, status, coverage, capabilities,
observations, limitations, errors, delta, local-policy result, destination,
action, deadline, and the warning that signed and analysed do not mean safe.

Review remains a separate displayed evidence dimension, but candidate v1 has
no review-evidence record and therefore reports it as not supplied/not
established. It is not silently omitted, inferred from a signature, or filled
with caller prose. A future portable review attestation needs its own closed
subject/snapshot, reviewer, signature, time, revocation, scope, and limitation
schema before its digest can enter an assessment.

Caller text may appear only as an untrusted annotation. It cannot select a
provider, invent a capability, suppress a finding, downgrade an unknown, or
construct the prompt. The future prompt must follow
[the accessibility contract](ACCESSIBILITY.md). Command-line text and `--yes`
are not substitutes for it.

## Deliberate non-claims

This evidence does not establish:

- absence of malware or vulnerabilities;
- behaviour of every runtime path;
- safety of remote services, future downloads, or post-install updates;
- truthfulness of comments, manifests, provider output, or publisher claims;
- legal identity, copyright ownership, code review, or current authorization;
- organizational independence of Plug & Prejudice;
- freshness or portability of an unsigned operation-local assessment; or
- that a provider, adapter, policy, registry, UI, or A Quo is defect free.

Runtime containment, least privilege, review, reputation, revocation,
rollback, and incident response remain separate controls. A signature proves
only what its verification and subject binding establish. Analysis proves only
what the named provider, exact input, declared coverage, and limitations
support.

## Non-circular implementation and acceptance stages

No stage may claim success by depending on the result it is meant to establish.

### Stage 0: candidate schema freeze (#8)

Freeze this design only after machine-readable schemas, registry and stream
parsers, golden JCS/stream vectors with recorded digests, enum/bound tests,
failure variants, delta vectors, and the operation-assessment threat decision
are reviewed. Until then, incompatible candidate changes are allowed and no
implementation may advertise v1 compatibility.

Implemented toward this gate: the common manifest subject; closed publisher,
structure, update-delta, local-policy, policy-result, and assessment types;
machine-readable JSON Schemas; bounded exact-JCS Rust parsers; canonical
encoders/digests; structural internal-invariant checks; the narrowly named
shape-and-binding helper; exact file-delta, publisher-continuity, plugin-ID,
and SemVer-precedence derivation; one checked-in blocked/indeterminate golden
update with no permission or coverage claims and with tamper/failure tests; and
a seeded coverage-guided byte-parser target.

Still open before Design exit: machine-readable provider-registry and evidence-
envelope schemas/parsers; the binary stream constructor/parser and zero/edge
vectors; full tagged-envelope/status and reference vectors; exhaustive enum,
bound-plus-one, ordering, containment, and mismatch cases; provider-envelope
semantic recomputation for capability policy; frozen isolation profiles and
resource limits; the operation-assessment threat decision/evidence matrix;
sustained fuzz campaigns and coverage evidence; and review against the exact
candidate revision.

**Current status: Design with a Stage-0 referenced-record shape/binding
prototype; schema freeze incomplete. No component advertises v1
compatibility.**

### Stage 1: immutable corpus (#10)

Freeze canonical packages, proofs, manifests, update pairs, and hostile
variants under [the Layer 1 corpus criteria](OMARCHY-CORPUS.md). This does not
require a provider, prompt, accessibility bridge, installation, or clean-system
result. It supplies independently identified inputs to later analyzer tests.

### Stage 2: analyzer conformance (#8/#9)

Against frozen Stage 1 artifacts, implement and test the stream, registry,
component verification, isolation, adapters, tagged envelopes, capabilities,
hostile decoding, failures, and deltas. Record exact component, isolation,
stream, report, coverage, claim, limitation, and error expectations. This can
establish analyzer conformance without claiming a trusted install journey.

### Stage 3: trusted product integration (#6/#7/#9)

Only after relevant Stage 2 results exist, implement the operation-local
assessment, closed policy, single-use deadline binding, accessible trusted
prompt, and same-snapshot install/update handoff. Clean-system tests then cover
consent, installation, update, rollback/interruption behavior, and stale
assessment rejection under [the package contract](PACKAGING.md).

Release acceptance additionally requires hostile-input testing, fuzzing,
keyboard/assistive-technology checks, and proportionate independent security
review. Passing Stage 3 still does not mean every signed or analysed plugin is
safe.

Until these stages are complete, this document is planned work for issues #8
and #9. The current product remains a prototype with structural inspection,
not a release-ready scanner or install-policy gate.
