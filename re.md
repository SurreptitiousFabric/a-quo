# Issue #68 — production signing authority with protected local consent

## Status, scope, and repository basis

On 2026-09-05 the owner selected the separation of protected local signing
consent, independent history assurance, and additional whole-machine rollback
prevention, and requested this definition. This document records that design
decision and reconciles the protocol around it. It supersedes the earlier
external-approval-device baseline in this file.

This remains design work for general Linux 0.x deployments. Asahi is the
inspected reference target, not a required operating system, kernel fork,
architecture or product dependency. No service, signer integration, proof
implementation, privileged configuration, migration, hardware experiment,
wallet transaction signing, commit, or GitHub change is authorized by this
document. Implementation and independent security review remain separate work;
owner selection of a direction is not evidence of implementation correctness.

| Repository fact checked for this revision | Value |
|---|---|
| Repository | `/home/swa/src/a-quo` |
| Local branch and HEAD | `issue-65-prepare-isolated-gpgv-runtime` at `bd139ffe48a5c2834698a82e4d0c94394b81d6f7` |
| Locally retained `origin/main` | `a10a371f2bed300a78beabc72f58bf27abc31b8d`; this revision makes no new live-remote-head claim |
| Relevant continuity/store/contract comparison | No difference between those local revisions |
| Edited artifact | Untracked `re.md`; no tracked source or staged changes at the start |
| Issue scope | [#68](https://github.com/SurreptitiousFabric/a-quo/issues/68), design only |
| Supporting investigation | [report4.md](report4.md), including the distinction between checkpoint detection and preventive signer gating |
| Revision validation | Document consistency, prior acceptance-vector coverage, source/link checks and whitespace; no runtime or hardware tests |

The checked-out branch does not continue issue #65. Prior reports are dated
investigations, not normative requirements for this revised design.

## 1. Selected decision in one page

### 1.1 Architecture and assurance selection

1. The desktop-UID daemon remains an unprivileged coordinator, proof builder,
   and explicitly selected Tier 2 path.
2. A static, non-root, separate-UID authority service owns Tier 3 persona,
   policy, continuity, enrollment, request, and terminal-result state.
3. A narrow signer endpoint exposes only enrolled, per-persona provider slots
   unavailable to the desktop UID.
4. A system-owned outer compositor retains physical display and input control.
   The ordinary desktop compositor runs nested in it. A protected native
   consent service obtains exact request-specific approval after a reserved physical attention
   gesture. The built-in display and keyboard may serve this profile.
5. Baseline `higher-assurance-v1` requires protected local consent, protected
   local state, exclusive signer access, and crash/replay correctness. It
   neither requires a phone nor claims independent whole-machine rollback
   prevention.
6. Independent history assurance compares valid portable history with
   separately obtained root, exact-head and recovery-policy expectations.
   It is available independently of the signing tier and reports the limits
   of its checkpoint's provenance and freshness.
7. Prevention of signer use after whole-machine rollback is a separate,
   policy-required extension. The baseline cannot satisfy that requirement
   and rejects it before consent or signing. A future extension must qualify
   its complete signer gate, not merely add a post-sign checkpoint.
8. Each persona has unrelated authority-attestation and protected-consent
   keys. Host identity, shared device identity, certificates, accounts and
   common enrollment handles do not appear in ordinary portable evidence.
9. The authority signs a receipt over canonical semantic signed material.
   The unprivileged builder creates the unchanged portable proof after
   verified atomic commit and committed-state reread.
10. Each first submission carries a caller-generated 256-bit nonce. The nonce
    and complete request digest drive exact query, retry and conflict handling.
11. Tier 2 migration uses one ordinary dual-signed routine transition:
    exactly one previous-key and one next-key SSHSIG over identical existing
    canonical bytes. Tier 3 begins there and never relabels earlier history.
12. Missing required assurance fails closed. A separately initiated Tier 2
    operation may coexist; no failed Tier 3 operation silently becomes Tier 2.

The selected consent profile is `protected-local-v1`. It is a design to build
and qualify using existing Linux facilities. It has no browser, phone or
future upstream Linux security feature as a prerequisite. General Linux
systems can qualify against the same requirements; support is established
for actual system/driver/session combinations, not inferred for every distro.
The present desktop configuration does not already provide this boundary.

### 1.2 Product and scope invariants

- A Quo remains an identity, exact-byte signing, persona, continuity, recovery
  and trust-evidence system.
- Persona separation prohibits a stable portable value introduced by A Quo
  that deterministically correlates otherwise separate personas.
- Plug & Prejudice owns behavioural plugin analysis.
- Ordinary malware running as the desktop user is in scope. The kernel,
  administrator, protected compositor/consent/authority code and qualified
  provider are trusted. Their compromise is outside the baseline claim.
- Private persona keys and official-wallet credentials remain with their
  provider, hardware, agent or official wallet where possible.
- Official identity-wallet presentation remains the wallet scope. Direct
  cryptocurrency/blockchain transaction signing requires a separate product
  and threat-model decision.
- Portable proof semantics and offline verification do not depend on the
  Linux authority service or an AuthorityReceipt.
- General proof, archive, media, wallet-presentation, plugin and report parsing
  stay outside the authority. The consent service receives bounded derived
  signing facts, not those source formats.
- Root ownership, a different UID, hardware touch or a valid signature alone
  cannot establish informed consent, software safety or legal identity.

### 1.3 Evidence classes

| Evidence class | Can establish | Cannot establish by itself |
|---|---|---|
| Local installation qualification | Evaluated service, process, device and policy boundaries on an exact installation | Portable legal identity, independent witnessing or absence of kernel bugs |
| Portable persona authority evidence | A persona-enrolled receipt key signed the exact canonical material under its declared consent/assurance profile | Current global authorization, trusted time, whole-machine rollback prevention or human understanding |
| Independently retained history expectations | Agreement or disagreement with the specifically expected root/head/policy | Freshness or completeness beyond the expectations, or prevention of an earlier signer invocation |
| Qualified preventive rollback mechanism | Only the externally enforced state and signer-use guarantees of its accepted profile | Consent, artifact safety, protection of unrelated keys or every conceivable rollback |
| Hardware/manufacturer attestation | Properties documented by a qualified attestation profile | Persona identity, exact consent, unlinkability or legal identity |
| Legal/organizational identity | Separately issued identity evidence under its own policy | It is not created by these signatures or local service identities |

## 2. Assurance properties and exact claims

### 2.1 Signing and verification tiers

| Tier | Exact positive claim | Operations and evidence | Failure behaviour |
|---|---|---|---|
| Tier 1 — portable verification | A valid portable proof binds its exact canonical statement and key; artifact bytes match where required | Existing proof formats, continuity/recovery rules and verifier-owned pins | Report cryptographic validity separately from trust and current authorization |
| Tier 2 — trusted desktop | Under a trustworthy desktop/display assumption, the current daemon signs the sealed, revalidated statement after its separate consent flow and verifies before return | Existing desktop-accessible OpenSSH/agent/FIDO providers and current closed operations | Explicit `trusted-desktop` selection; cannot satisfy Tier 3 |
| Tier 3 — protected local authority | Under the stated system/provider assumptions and protected local state, desktop-UID malware cannot alter the approved authority-canonical operation, forge its exact consent, directly use its qualified signer, advance authority without every mandatory verified signature, or obtain a receipt for different material | Closed operations; `protected-local-v1` consent; exclusive providers; unchanged proofs plus optional portable per-persona enrollment/material/receipt evidence | `higher-assurance-v1`; failed required dependencies or unsupported stronger policy block the operation |

The optional nature of exporting a receipt does not make its creation,
verification and protected retention optional. A portable verifier without the
required enrollment/material/receipt evidence cannot report the Tier 3 claim.

For migration, pre-transition evidence remains Tier 2. A receipt-aware
verifier must independently accept the persona root and authority enrollment
before trusting the authority claim. A cryptographically valid self-enrollment
does not prove the installation was qualified.

### 2.2 Baseline local assurance

Baseline Tier 3 requires all of the following:

- protected physical display/input and exact, per-request consent;
- protected persona, policy, history, enrollment, signer-slot and result state;
- rejection of stale request expectations and desktop-controlled state or
  signer substitution;
- durable, atomic commit, complete post-sign verification, one-use consent
  acceptance, nonce tombstones and exact committed-result replay;
- closed handling of cancellation, timeouts, interrupted writes, uncertain
  provider outcomes, detected corruption, known restore and missing state;
- no automatic restoration of authority from user-owned mirrors or archives.

Its policy is the **protected locally accepted policy**, not a claim that no
newer external policy or history exists. The baseline excludes undetectable
coherent restoration of the complete protected system state, including every
local checkpoint and relevant operation journal. A local hash or signature
does not turn that exclusion into detection.

This exclusion does not cover a restore API or filesystem path reachable by
ordinary desktop malware: such access violates the baseline isolation
requirement. Known state loss/restore freezes new signer work until the closed
recovery rules are met. Partial-write and ordinary crash correctness remain
mandatory.

### 2.3 Independent history assurance

This property is independent of tiers 1–3. A trusted verifier checks:

- a separately obtained persona-root statement digest;
- an exact expected continuity sequence and transition digest, when supplied;
- explicit recovery-policy expectations, including absence when applicable;
- the validity and authorization of the complete supplied history.

The existing core can require an exact head match. Root-only verification
accepts valid historical prefixes; an exact later checkpoint rejects an older
head or different branch. Archive comparison additionally distinguishes an
exact match, a matching extension beyond a pin, divergence at/before it, and a
shorter inconclusive candidate. Those comparison outcomes are not permission
to activate a signer or select the longest branch.
[Continuity contract](docs/CONTINUITY.md#status-and-meaning),
[archive comparison](docs/CONTINUITY.md#independent-checkpoint-comparison)

Reports preserve separate facts: proof validity, which expectations were
checked, their relationship to the supplied history, and what is known about
source independence/freshness. A match is relative to that checkpoint; it
does not prove absence of a later or withheld sibling history. Pins copied
from the same untrusted collection supply consistency, not independence.
A checkpoint restored with the same machine cannot witness that restoration.

The existing checkpoint verifier is implemented. Independently witnessed
publication and freshness infrastructure remain pending under continuity
work; no existing persona-witness service is assumed here.
[Pending work](docs/CONTINUITY.md#deliberately-pending)

Baseline signing still enforces each operation's required root/head/policy
expectations. An untrusted caller cannot replace protected pins or make its
own supplied values count as a fresh independent witness. External history
checks by relying verifiers do not require a phone, approval-device pairing,
or a change to portable proof semantics.

### 2.4 Additional whole-machine rollback prevention

This property means preventing a **new use of a qualified gated signer under
stale relevant authority state**, within the stated scope of a separately
qualified profile. Detecting stale evidence after signing is weaker and must
be labelled accordingly. Neither property provides trusted consent.

The closed policy distinction is `rollback_requirement = not_required` or
`required`. The minimum `protected-local-v1` profile can issue material only
with `not_required`. It recognizes a request or enrollment requiring the
stronger property and returns `UnsupportedAssurancePolicy` before pending
acceptance, consent or any signer use. Existing protected policy may never be
overridden by the caller. Unknown requirement values are invalid.

A future qualifying extension must define and demonstrate:

1. State retained outside the rollback domain, plus authenticated enrollment,
   policy changes, recovery and revocation for each persona.
2. Coverage of the promised state: root, effective history and recovery-policy
   heads, authority/enrollment/security epochs, relevant signer/policy state,
   and operation/result/receipt state when duplicate-use prevention is claimed.
   A continuity head alone omits ordinary artifact-signing results.
3. An authenticated per-operation authorization before signer access, bound
   to exact persona, operation, nonce/request digest, expected state and signer
   role. Replayed responses or evidence obtained only after signing cannot
   satisfy it.
4. Enforcement that survives restoration of old local policy or software. A
   local flag saying "consult the witness" is insufficient. The qualified
   provider or another enforcement boundary outside the restored image must
   reject bypass. Restoring an earlier `not_required` configuration must not
   unlock the gated signer.
5. Serialization, expiry/freshness, replay, concurrency, cancellation, crash
   and completion rules. A reservation may block competing proposals but
   must not advance accepted persona authority before all signatures and
   verification. Distributed completion cannot be described as a single
   ordinary SQLite transaction.
6. A precise signer-invocation and result-release guarantee, including what
   happens when authorization succeeds but a result or completion acknowledgement
   is lost. Unknown outcomes never justify repeating signer work.
7. Persona privacy: independent per-persona bindings, no mandatory universal
   identity, and explicit service/traffic correlation limits.

A transparency inclusion proof alone is not unique-head selection or a fresh
signer gate. Old ancestor keys and already released signatures are not
retroactively disabled by this extension.

No concrete witness/hardware protocol is qualified in this definition.
Required deployments remain unsupported until a separate closed profile and
its tests meet these obligations. This is independent work, not a dependency
for defining or qualifying the baseline local-consent tier.

### 2.5 Policy and reporting

| Item | Baseline meaning and rule |
|---|---|
| `assurance_tier` | `higher-assurance-v1`: the local claim in §2.2 |
| `consent_profile` | Exactly `protected-local-v1`; binds the native protected physical path |
| `rollback_requirement` | Exactly `not_required` in issued baseline enrollment/material |
| History comparison | A separate verifier result naming its actual expectations and limitations; never inferred from the authority's tier label |
| Stronger required policy | Unsupported before signer access in this baseline; no downgrade or skipped check |
| Offline verification | Preserves historical proof/receipt validity; does not make a live freshness or preventive-rollback claim |

The three fields above are common protocol constants, not installation IDs.
An operation's effective requirements are at least the protected persona
policy and may be strengthened by the request, never weakened. Unsupported
strengthening is rejected. Requirements are covered by request digest,
consent and receipt material; a display-only label cannot change them.

A requirement for fresh external evidence has the same fail-closed rule:
without a qualified acquisition/authentication profile it is unsupported.
Separately retained exact pins can still be verified through the existing
history mechanisms. A failed independent-history check cannot be displayed as
a successful current-authorization result merely because local consent or a
portable signature verified.

## 3. Component and authority boundaries

### 3.1 Selected process split

The current sealed snapshots, typed private IPC, provider-policy checks and
post-sign verification remain useful. Its desktop UID and user-owned store
do not become Tier 3 authority. The selected local split is:

```text
Physical display and enrolled keyboard/input
                 |
System supervisor -> protected outer compositor (dedicated UID)
                       |                          |
                       v                          v
                nested desktop           native consent service
                desktop UID              separate protected UID
                untrusted content        exact derived request/decision
                       |                          |
                       | closed proposal          | private authenticated
                       v                          | SOCK_SEQPACKET
                a-quo-authorityd <-----------------+
                separate authority UID
                protected per-persona policy/history/request/result state
                       |
                       | closed broker-only signer protocol
                       v
                qualified a-quo-signerd / provider
                exclusive per-persona slots

After verified commit and reread:
authority -> material + receipt -> unprivileged builder -> portable verifier

Independent history expectations -> verifier as a separate evidence input
Official identity wallet -> presentation handoff only; never this signer path
```

The system supervisor only arranges fixed services, device ownership and
protected connections. Compositor, consent renderer, authority and signer run
with bounded distinct responsibilities. The privileged setup component does
not parse general signing requests or run the complete existing daemon as root.

| Component | May do | Must not do |
|---|---|---|
| CLI/UI and desktop daemon | Snapshot inputs, propose bounded operations, persist caller nonces, relay public evidence, build/publish proofs, run explicit Tier 2 | Write protected state, forge consent, choose arbitrary Tier 3 locators or reach its signer directly |
| System supervisor and outer compositor | Own physical display/input, launch fixed protected components, consume the physical attention gesture, isolate nested desktop presentation | Accept consent authority from desktop window identity, virtual input, scripts, arbitrary executable names or D-Bus |
| Native consent service | Authenticate authority request, display exact facts, receive qualified physical input, issue a one-use per-persona approval token | Trust desktop content, process archives/media/proofs, import persona keys, or treat a local token as independent rollback evidence |
| Authority | Validate closed inputs, construct canonical statements, enforce protected local state/requirements, verify consent/signatures and atomically commit | Traverse the home, accept arbitrary paths/commands/methods, build general proof/archive formats, expose UI or generic signing |
| Signer endpoint | Resolve fixed persona slots, enforce exact authority/role/namespace binding, journal queryable outcomes | Accept caller-selected keys, paths, agent sockets, namespaces, arbitrary bytes or commands |
| Proof builder | Assemble unchanged portable proofs and optional receipt evidence after commit | Change authority, reinterpret consent or claim a receipt covers its serialization/path |
| Independent verifier | Bounded hostile parsing; verify portable proof first, then enrollment/material/receipt and independent history expectations | Infer global freshness, trusted time, legal identity, installation qualification or rollback prevention from a valid signature |

Authority and signer have no general network, home access, shell,
caller-selected subprocess or ambient capability. Narrow service/runtime
directories and fixed Unix endpoints are defence in depth. The compositor's
ordinary Wayland client connection carries nested desktop surfaces and input;
A Quo signing/consent messages still use the closed private Unix-socket
boundary. Optional buses provide discovery only.

### 3.2 Exact edge and authority-flow map

| Edge | Carried values and creator | Validation and storage | Attacker capability and ultimate trust |
|---|---|---|---|
| Caller → desktop coordinator | Caller nonce, persona/root, closed purpose/display metadata, expected state/provider, opened input | Coordinator seals input and retains non-authoritative retry record | Same UID can replace proposals or pre-snapshot bytes; none is trusted merely because the coordinator supplied it |
| Coordinator → authority | Sealed FD where applicable, complete closed request and minimum assurance requirements | Authority validates framing/seals/bounds/state, reconstructs statement/RD and reserves only Pending | Malware may submit/replay bounded proposals; protected state and exact consent decide authorization |
| Physical input → outer guard | Actual events from already enrolled, system-exclusive physical devices | Guard owns FDs and consumes attention/decision gestures; no raw-key logging | Desktop virtual input is not a physical consent source |
| Nested desktop → outer guard | Untrusted surfaces/buffers and ordinary client requests | Bounded compositor protocol; only untrusted presentation role | Desktop cannot select protected layers, capture protected content, suppress attention or inject approval |
| Authority → consent service | Exact canonical facts/digest/size, persona, purpose, policy/head, roles/providers, N/RD, requirements and fresh challenge | Protected endpoint authentication; persona authority pin; guard-instance/display binding; bounded display | An ordinary desktop relay or fake service has no trusted connection; no global host identifier enters portable evidence |
| Consent service → authority | Per-persona signed decision bound to challenge, N/RD, operation/state/requirements, expiry and protected instance | Live protected-instance validation, one-use durable acceptance and acknowledgement; safe digest retained | Only this exact accepted result permits signer work; local signing of the token proves no off-machine checkpoint |
| Authority → signer | Persona, operation/N/RD, exact statement/digest, fixed role/namespace, enrolled slot and expected key | Signer authenticates broker, validates fixed enrollment and journals exact provider outcome | No desktop-selected locator or generic method reaches the provider |
| Signer → authority | Required signature(s), normalized public key and exact tuple/role binding | Authority verifies complete set, bytes, roles, keys, policy and complete chain | Wrong/partial/uncertain results cannot become success |
| Authority → protected store | Pending records first; at final CAS, authority delta plus exact material/receipt/result | Atomic commit, durability and committed-state reread | Only Committed changes authority; baseline has no external checkpoint acknowledgement |
| Authority → builder | Exact verified statement/keys/signatures, canonical material and enrollment/receipt after reread | Builder independently verifies and assembles unchanged proof | Desktop may alter or withhold outputs; verifier detects semantic changes |
| Proofs and separate pins → verifier | Portable evidence plus independently obtained expectations | Bounded proof/receipt/history verification; separate results | Checkpoint agreement is relative, not a global freshness or pre-sign enforcement claim |
| Official wallet ↔ presentation adapter | Presentation request/response, audience, nonce, disclosed credentials under that protocol | Wallet and presentation verifier keep their custody/validation roles | Never becomes an A Quo signer or consent authority |

Private persona keys and wallet credentials never cross these edges.
The authority reconstructs exact signing bytes; the desktop supplies proposals,
not policy authority. The consent service holds only its own protected
per-persona approval keys, not persona signer keys.

### 3.3 Protected assets

| Asset | Baseline protection | Limit or separate assurance |
|---|---|---|
| Artifact/statement and purpose | Sealed snapshot, independent canonicalization/hashing, exact protected consent and post-sign checks | Authentically displayed deceptive content and social coercion remain risks |
| Consent decision | Protected physical input/display, distinct service UID and exact one-use result | Protected compositor/service compromise is outside the claim |
| Persona/policy/history | Service-owned store, full verification, exact expected state and CAS updates | All-local coherent rollback excluded; independent history/prevention are §2.3/§2.4 |
| Signer locator, agent and hardware channel | Fixed enrolled service-only slots, identity revalidation and no desktop access | Every actual provider must qualify; a hardware touch alone is insufficient |
| Request/result/receipt journal | Durable nonce mapping, complete verified results, tombstones and exact retry | Neither local counters nor local hashes witness restoration of themselves |
| Approval key and enrollment | Fresh per-persona key in protected consent custody, local authenticated binding | Key/record loss is known loss requiring closed reconciliation; no phone checkpoint assumed |
| Proof files, archives and user SQLite | Evidence/cache only; independently parsed and verified | Cannot create or restore authority by themselves |
| Recovery evidence | Existing pins, threshold rules, complete chain and operation-specific consent | Witness freshness and authorized recovery routes must be established separately |
| Wallet transcript | Remains inside presentation-specific semantics | No wallet custody or transaction-signing claim |

### 3.4 Candidate comparison and deployment conditions

| Candidate | TCB/privilege/state | Capability and remaining gap |
|---|---|---|
| Current per-user daemon | Desktop UID, user store/config and accessible providers | Preserves Tier 2; lacks same-user isolation and protected display/input |
| Small separate-UID broker | Fixed system endpoint, bounded parser, protected policy/store, no general network | Isolates policy; still needs exclusive signer and exact protected consent |
| Root-owned launcher with ordinary worker | Small privileged startup plus worker | Startup ownership alone does not protect a desktop-UID worker or its UI |
| Separate UID and exclusive hardware/agent signer | Service-only provider channel and protected state | Isolates signer access; touch/UV is not exact-statement display |
| Separate trusted display device | Device-specific keys, firmware, protocol and lifecycle | May supply a separately qualified consent profile; not selected or required by baseline |
| Official-wallet handoff | Wallet presentation protocol and credential custody | Presentation only; does not provide this signing or consent authority |
| Reserved VT with protected input | System VT/device helper and native renderer | Possible local alternative; hostile display handoff needs separate qualification |
| Stock SAK, ordinary lock or Wayland surface | Kernel signal or desktop compositor/UI | Does not alone supply the composed trusted-consent/result boundary |
| Selected local construction | System outer compositor/native consent plus separate authority and exclusive provider; narrow privileged setup | Retains physical ownership, supports existing keyboard/display, and scopes independent history/rollback separately; larger compositor/client-parser TCB requires testing |

The selected profile changes session startup and system device permissions.
The desktop must have neither physical seat access through the installed seat
manager nor raw evdev, hidraw/usbfs, uinput, framebuffer/KMS or root-equivalent
administrative paths capable of defeating the guard. Examples include
rootful container sockets, unattended privilege rules and device-management
APIs; membership names alone are not the security test. A clean trusted
startup establishes ownership before the untrusted desktop; changing a mode
bit does not revoke old FDs.

The guard controls all outputs/planes/cursors, handles suspend/hotplug/VT
lifecycle, and uses protected unshared buffers for consent. Nested-client
render fences, captures, pointer locks and shortcut inhibitors cannot become
approval authority. Rendering may use a render node without granting physical
display control. Kernel graphics and input drivers remain in the trusted
base; their existence is not proof that a particular installation is isolated.

Accessible visual, keyboard and protected speech/output paths are part of
qualification. The cost includes compositor/protocol attack surface,
administration, session startup, remote-control/capture changes and recovery.
Availability, malicious kernel/firmware, root-equivalent control and coercion
remain explicit limits. No existing local prototype is called production-ready
merely because these interfaces exist.

### 3.5 General Linux contract and target qualification

The normative contract is the same across Linux distributions and CPU/GPU
families. It requires a protected physical presentation/input owner,
authenticated protected local services, an untrusted nested desktop, exclusive
signer access, and the state/protocol invariants in this document. It does not
select an Asahi API, Apple device, Hyprland version, package manager or init
system as a portable assurance field.

| General Linux requirement | Per-target qualification evidence |
|---|---|
| Protected physical display ownership through DRM/KMS or an equivalently isolated Linux display path | Actual driver/device topology; ownership of every relevant output, plane and cursor; suspend, hotplug and teardown behaviour |
| Physical attention and decision input unavailable for desktop injection | Exact physical-device enrollment, device-node permissions and open-FD lifecycle; virtual input, device-management and remote-control paths tested |
| Protected process, filesystem and local IPC boundaries | Service identities, installed supervision/sandboxing, endpoint authentication, update/recovery rules and denial of desktop privilege paths |
| Ordinary desktop isolated as a client | Supported nested compositor/backend and buffer/protocol negotiation; no grant of physical device or protected-surface authority to make it work |
| Protected visual and accessible consent | Rendering, input layout, usable exact-field disclosure and any required audio/output isolation tested on that target |
| Qualified exclusive provider | Actual signer custody, namespace/role enforcement, result recovery and desktop-access denial |

The Linux kernel documents the separation of render-node access from modeset
privilege. Weston documents DRM/input and nested Wayland backends as existing
building blocks. These support the engineering feasibility inference; neither
document supplies an already qualified A Quo consent product.
[Linux DRM render nodes](https://docs.kernel.org/gpu/drm-uapi.html#render-nodes),
[Weston backends](https://wayland.pages.freedesktop.org/weston/toc/running-weston.html)

The first inspected target is Arch Linux ARM/Asahi on Apple hardware, using
Hyprland with Aquamarine and systemd/udev. Its separate display/render devices,
the installed nested backend's DMA-BUF/protocol requirements, speaker-safety
requirements and observed Docker/input access are **target qualification
facts**, recorded in [report4.md](report4.md). They must be resolved on that
target without weakening the general contract. Another distribution, init
system, compositor or GPU may use different integration details and satisfy
the same tests. A target that cannot do so is unsupported for this profile;
it does not redefine the assurance tier.

## 4. Persona-unlinkable authority identity

### 4.1 Per-persona construction

For every persona (P), Tier 3 creates these independent values:

- `authority_attestation_key_P`: a fresh Ed25519 key pair generated from the
  operating system CSPRNG inside the authority boundary. Its private key is
  non-exportable to the desktop UID and is held in the service-owned store or
  a qualified provider. It is never derived from a host key, account key,
  installation secret, device certificate, another persona, or a publicly
  provable common parent.
- `authority_key_id_P` is computed as:

  ```text
  base64url_no_pad(
    SHA-256("AQUO-PERSONA-AUTHORITY-ID-V1\\0" || raw_ed25519_public_key_P)
  )
  ```

  It identifies only that independently random key.
- `approval_key_P`: a fresh Ed25519 key created and held by the protected
  native consent service for this persona. Its public key is authenticated to
  the authority over the system-established enrollment channel. It signs
  exact local consent results; it is not an independent witness or a
  whole-machine rollback anchor. The key and its enrollment stay local.
- `provider_enrollment_id_P`: a fresh random per-persona identifier for each
  allowed signer slot. A device serial, agent identity, account identifier,
  certificate serial, or common provider handle is never substituted for it.
- Persona signing keys are distinct per persona for Tier 3 enrollment. The
  authority rejects known reuse of an authority key, approval key, provider
  enrollment identifier, portable attestation value, or Tier 3 signer public
  key across its personas.

A physical provider or protected service may protect several per-persona keys
within its assigned custody role only if ordinary portable evidence exposes no common derivation, device certificate,
attestation chain, serial, account, stable enrollment handle, or public key.
If a provider cannot suppress or replace a linkable shared attestation value,
that attestation is local-only or that provider is not eligible for the
ordinary privacy-preserving portable Tier 3 profile.

The service may have a local diagnostic `service_instance_id` and the package
may have local installation facts. They are outside trust, stay in
service-level diagnostics, are never copied into a persona or request record,
and are prohibited in receipts, proofs, attestations, exported evidence, QR
data, public cards, and verifier-facing reports. No receipt or retry relies on
them.

### 4.2 Portable enrollment

`AuthorityEnrollmentV1` is a separate bounded portable object. It does not
change any existing proof schema. Its canonical enrollment statement contains:

| Field | Binding |
|---|---|
| `schema`, `canonicalization`, `protocol_version` | Closed values for the enrollment format |
| `persona_anchor`, `persona_root_statement_sha256` | The one portable persona history selected by a verifier-owned root pin |
| `activation_head` | Exact continuity sequence and transition-statement digest at which this authority key becomes eligible |
| `authority_key_epoch` | Ordered within this persona's retained enrollment history; starts at 1; not an independent rollback counter |
| `authority_signature_algorithm` | Exactly `ed25519` in v1 |
| `authority_public_key`, `authority_key_id` | Exact per-persona receipt-verification key and its domain-separated ID |
| `prior_authority_key_id` | Absent at initial enrollment; the prior key of this same persona for a replacement |
| `consent_profile` | Exactly `protected-local-v1` for this baseline enrollment |
| `rollback_requirement` | Exactly `not_required`; `required` cannot be enrolled by the baseline |
| `portable_attestation` | Must be absent in the ordinary v1 profile |

The proof contains two signatures over identical canonical enrollment bytes:

1. a persona-authorization SSHSIG made by the persona key authorized at
   `activation_head`, using the closed namespace
   `a-quo-authority-enrollment-v1`; and
2. an Ed25519 proof-of-possession signature by
   `authority_attestation_key_P`, domain-separated as
   `AQUO-AUTHORITY-ENROLLMENT-POSSESSION-V1`.

An enrollment replacement also requires the old authority key to sign the
same replacement statement under
`AQUO-AUTHORITY-ENROLLMENT-REPLACEMENT-V1` when that key remains available.
The verifier checks the persona root pin, the complete continuity chain through
`activation_head`, the persona signature against the key active at that
head, the new authority-key possession signature, the same-persona
prior-key/epoch link, and any later replacement or revocation evidence.

This makes the receipt key meaningful only inside one persona history.
Substituting persona A's enrollment into persona B fails the root, anchor,
active persona key, and enrollment signatures before receipt trust is granted.

### 4.3 Initial binding and lifecycle

System-authenticated local enrollment binds the authority's persona-specific
public key, consent public key and provider slots before any of them become
active. The supervisor connects the fixed protected services; each validates
the peer identity and exact persona/anchor/key material from that channel.
Neither a desktop-rendered QR, a caller-selected socket nor a public-key
self-signature supplies this bootstrap trust. The user sees and approves the
binding through the protected physical ceremony in §11.3.

Pending key provisioning is an enrollment step under these protected services,
subject to bounded quotas. It creates no persona authority and performs no
persona signature. The proposed public keys/IDs and profile requirements are
fixed before the caller constructs the complete signing request and saves its
nonce; secret pending material stays in its respective protected custodian.
A request cannot silently replace these fields after its digest is reserved.

| Lifecycle event | Required binding and atomic result |
|---|---|
| New Tier 3 persona | Use the fresh persona anchor, Tier 3 signer key, authority key, approval key, and per-persona provider IDs from protected pending enrollment. The initial persona signer signs the unchanged root statement and the enrollment statement; the authority key proves possession. After all signatures, material, and receipt verify, one commit creates the root, active signer, enrollment with exact profile/requirements, policy/head, and terminal result. |
| Existing Tier 2 persona migration | Verify the independently pinned root and complete existing chain. The exact next routine transition is dual-signed by the previous Tier 2 key and new Tier 3 key. The new key also signs the authority enrollment. Only one commit activates the new signer and per-persona authority identity. Section 10 defines the bridge and nonclaims. |
| Planned authority-service/key replacement | Generate a new unrelated per-persona authority key. With protected local Tier 3 consent, the current persona signer, old authority key, and new authority key sign one replacement enrollment. Commit activates the new epoch and revokes the old key for later receipt sequences. No host identity carries over. |
| Lost consent key/enrollment | Freeze new signer work. A qualified protected reenrollment ceremony must validate the retained persona authority, current local state and provider bindings and record a fresh per-persona consent key; user files or an unsigned desktop pairing cannot restore authority. If that recovery path is not implemented and qualified, require existing authorized recovery or a new persona. |
| Profile or rollback-requirement change | Never a request-side edit of enrollment. A supported change must have exact protected consent and a signed, persona-bound policy/enrollment lifecycle transition. The baseline cannot activate `required`; an attempted strengthening fails closed. Changing local metadata cannot disable a future externally enforced gate. |
| Lost old authority service/key | Tier 3 stops. User-owned files alone cannot reconstitute authority. Replacement requires an already authorized recovery route that explicitly authorizes the new authority enrollment, or creation of a new persona. If neither exists, continuity is not invented. |
| Tier 3 signer replacement | Use the ordinary dual-signed routine-transition protocol: old active persona key is `previous`, new qualified key is `next`. The existing per-persona authority key may remain, but its receipt binds the new head and provider enrollment. The next key is inactive until atomic commit. |
| Lost previous signer | A routine transition is impossible. Use an already authorized recovery transition or create a new persona; never omit or replace the previous-key signature. |
| Authority-key revocation without persona termination | A canonical, persona-bound revocation/replacement object identifies the authority epoch and last allowed per-persona receipt sequence. It requires the current persona key or an already authorized recovery route and Tier 3 consent. A compromised old authority key alone cannot revoke or replace itself into trust. |
| Terminal persona revocation | The complete existing portable terminal-revocation proof is verified first. The final receipt is signed and committed with the terminal head; the persona, signer slots, approval enrollment, and authority key then become permanently inactive. No later receipt, key replacement, or signing operation is allowed. Historical receipts are not erased. |

Authority replacement and revocation order is defined by persona-local epochs,
continuity heads, and receipt sequences, not untrusted timestamps. A verifier
with only stale evidence cannot prove that no later revocation exists; current
non-revocation and global freshness remain nonclaims. Epochs and cutoff
sequences order retained evidence; the baseline does not independently detect
a coherent restoration of all enrollment, revocation and result records.

### 4.4 Portable, local-only, per-persona, per-request, and installation values

| Scope | Values | Export rule |
|---|---|---|
| Portable and per persona | Existing root/continuity/recovery proofs; persona anchor and root digest; persona signing public keys; `AuthorityEnrollmentV1` and same-persona replacement/revocation chain; authority public key/ID; per-persona policy/head identifiers; `AuthoritySignedMaterialV1`; `AuthorityReceiptV1` | May be exported. They intentionally correlate records within that one persona. |
| Portable and per request | Caller nonce, request digest, consent-result digest, operation, exact semantic material, signatures, result, persona-local receipt sequence | May be exported. Values are random or operation-bound and are never reused across personas. |
| Local-only and per persona | Consent public key/enrollment, provider slot endpoint and device mapping, local policy details not needed by the verifier | Never placed in ordinary receipts or verifier reports. |
| Local-only and per request | Raw approval token, fresh protected-ceremony instance, live acceptance/acknowledgement state, peer UID/PID, queue/rate data, provider diagnostics, cancellation timing, unreleased partial signatures | Never exported as receipt trust evidence. |
| Local-only and per installation | Service diagnostic ID, socket inode/path facts, package/unit identity, manufacturer/device qualification records, shared hardware serial/certificate/account facts | Never included in proof, receipt, enrollment, QR, public card, or verifier-facing report. |
| Common protocol constants | Schema names, algorithms, software-independent protocol versions, provider-class enums, consent profiles and assurance-requirement enums | May be portable; they identify a protocol cohort, not one installation or persona. Exact software build/version is omitted. |

`AuthorityReceiptV1` is available in both forms only in this precise sense:
the same portable, per-persona receipt is retained in the protected local
result record and may be exported. A separate local audit record may contain
nonportable diagnostics, but it is not an AuthorityReceipt, is never merged
into it, and supplies no portable trust.

### 4.5 Correlation review

| Potential correlator | Corrected treatment |
|---|---|
| Authority receipts | Different personas use unrelated authority keys/IDs and independent receipt sequences. No host/install field is present. |
| Persona public keys | Tier 3 requires distinct signing keys per persona. A user/provider that reused or published a key outside A Quo may already have linked personas; the protocol does not promise anonymity against that external information. |
| Device attestations | Shared chains, serials, AAGUID-like unique values, accounts, and device keys are excluded from ordinary portable evidence. Local qualification does not become portable proof. |
| Enrollment records | Bind only one root/anchor, per-persona authority key, and persona-local epoch. No common parent or installation signer appears. |
| Request IDs | The only portable request identity is a fresh caller nonce and its request digest. Neither is reused; no authority-issued global sequence is exposed. |
| Timestamps | Existing portable statement times remain and can support probabilistic correlation. The receipt adds no host clock or trusted-time claim. |
| Service versions | Exact service/package/build versions and installation IDs are omitted. A common protocol version is not unique and cannot deterministically link personas. |
| Policy identifiers | Portable policy/head digests are persona-root-bound. Shared local policy-template IDs are omitted. |
| Future independent witnesses | Use persona-specific bindings and disclose observer/traffic correlation limits. A common service identity is not copied into persona authority identity, and no such witness is required by the baseline. |
| Error metadata | Bounded closed errors are local-only and contain no provider path, device ID, authority instance, or cross-persona sequence. |

The narrower promised property is: A Quo itself adds no stable cross-persona
authority identifier or attestation value that deterministically links
otherwise separate personas. It does not promise anonymity against timing,
content, network observers, user key reuse outside the checked installation,
recipient collusion, or other external information.

## 5. Closed authority protocol and caller nonce

### 5.1 Transport and parsing

- Linux `AF_UNIX/SOCK_SEQPACKET` on a system-owned endpoint; optional buses
  may support discovery only. Signing and consent authority never use D-Bus.
- Magic `AQUOAUTH\\0`, closed protocol major/minor, closed message enum,
  zero reserved flags, and a 64 KiB control-packet maximum.
- Operation-specific schemas have `deny_unknown_fields` behavior, reject
  duplicate fields before canonicalization, reject noncanonical encodings, and
  bound every array/string/blob before cryptography.
- At most one sealed regular-file or memfd input per operation. Existing
  artifact and recovery-request size limits remain ceilings.
- No request contains an arbitrary path, command, executable, environment,
  provider method, SSHSIG namespace, signature role, signer locator, or generic
  byte-signing instruction.
- Every authority-to-signer call and signer-result query is keyed by the exact
  persona anchor, operation, caller nonce, complete request digest, signer
  role, canonical statement digest, and provider enrollment. The signer does
  not require an authority-generated identifier and cannot reinterpret a
  retry as a new operation.
- Persona is located by the immutable persona anchor and pinned root digest,
  never by the mutable display label. For new-root creation, the complete
  request contains a fresh proposed persona anchor, so the nonce can be
  reserved before an authoritative persona exists.

### 5.2 Caller-generated nonce and complete request digest

Every first submission includes exactly 32 cryptographically random bytes
(256 bits) generated and durably saved by the caller before sending. Binary
protocols carry the 32 raw bytes; JSON/display/export encodes them as exactly
43 unpadded Base64url characters. All-zero, wrong-length, padded, noncanonical,
or reused values outside the exact-retry rule below are rejected.

The authority computes:

```text
complete_request_digest =
  SHA-256(
    "AQUO-COMPLETE-REQUEST-V1\0" ||
    RFC8785({
      protocol_version,
      operation_type,
      persona_anchor,
      persona_root_statement_sha256,
      caller_nonce,
      assurance_tier,
      consent_profile,
      requested_minimum_rollback_requirement,
      effective_rollback_requirement,
      every operation field,
      exact sealed-input digest and size,
      exact expected policy/root/head/provider/enrollment state
    })
  )
```

File-descriptor numbers, paths, caller PID, queue timing, and local diagnostic
IDs are not semantic request fields. The authority validates and hashes the
complete sealed input before reservation; it does not begin consent, signer
work, or authority mutation first.

The request explicitly binds its requested minimum and effective requirements,
together with the exact expected protected policy generation. For a new
submission the authority checks that the effective values satisfy both the
request and the actual protected policy. It never silently weakens either.
The baseline admits only `higher-assurance-v1`, `protected-local-v1` and
effective `not_required`. A known `required` requirement or an unavailable
fresh-evidence policy yields `UnsupportedAssurancePolicy` before creating
`Pending`, displaying consent or using a signer. Unknown enum values are
`InvalidRequest`.

Bounded exact-retry lookup uses the originally accepted complete request and
requirements. It does not recompute their digest using a later policy and
mistake a historical result lookup for a new signing authorization. Retrieval
of an existing committed result makes no new current-policy or freshness claim.

The durable index is exactly equivalent to:

```text
(persona_anchor, operation_type, caller_nonce)
  -> complete_request_digest
  -> closed request state
  -> exact terminal result
```

For a new root, `persona_anchor` is the fresh proposed anchor in the complete
request. A separate protected uniqueness index rejects reuse of one caller
nonce by a different persona or operation in the same installation; this
prevents a malicious or broken caller from creating a portable cross-persona
correlator. Same-tuple lookup is evaluated first so legitimate exact retry
still works. Cross-installation deliberate reuse is external behavior and is
not an anonymity claim. Rules:

- Unused nonce plus one valid complete request creates exactly one
  non-authoritative `PendingRequest`.
- Same nonce plus the identical complete request returns or resumes the same
  state. No new consent or signer call occurs if already recorded.
- Same nonce plus any different digest returns `IdempotencyConflict` before
  consent, signing, or state mutation. The conflicting body is not retained.
- A committed request returns the byte-identical stored signed material,
  receipt, and operation result without consent, signing, or mutation.
- A declined, cancelled, expired, or failed request returns the same terminal
  disposition. A new attempt requires a new caller nonce.
- An indeterminate request can only be queried or reconciled through its
  closed operation-specific recovery path. It is never silently resubmitted
  and never changed into a different request.

`QUERY_RESULT_V1` takes `persona_anchor`, `operation_type`,
`caller_nonce`, and `complete_request_digest`. It needs no
authority-generated ID. It returns only a matching closed status or exact
terminal result; a wrong digest is `IdempotencyConflict`, not a lookup oracle.
`CANCEL_V1` uses the same four values.

Retention is unambiguous:

- Committed material/results and nonce mappings remain for the lifetime of the
  persona authority record, including its terminal archive.
- Terminal non-success records retain at least the tuple key, request digest,
  terminal disposition, and safe audit digest for the same lifetime. Bulky
  sealed input and provider diagnostics may be deleted after terminalization.
- A pending request on which no signer was invoked may be terminalized as
  `Expired` after the configured bounded abandonment interval; the nonce
  tombstone remains and can never be reused for that persona/operation.
- A request with a provider invocation or uncertain commit is never garbage
  collected as abandoned. It must reach a provable terminal result or remain
  `Indeterminate`.
- Per-persona and global pending quotas reject excess work before acceptance.
  A quota rejection is not an accepted submission; the caller must use a new
  nonce. Time used for housekeeping is operational only and is not trusted
  evidence.

### 5.3 Closed message families

| Message | Complete bounded request | Mandatory signers and result |
|---|---|---|
| `CREATE_PERSONA_ROOT_V1` | Nonce; fresh anchor; label; purpose; exact proposed initial public key and per-persona provider enrollment; proposed authority enrollment; expected persona absence | Initial Tier 3 persona signer signs root and authority enrollment; per-persona authority key proves enrollment possession and signs receipt; atomic root creation |
| `SIGN_ARTIFACT_V1` | Nonce; sealed artifact; persona/root/policy/head expectations; closed kind and bounded label; selected per-persona provider enrollment | Current active persona signer signs the existing canonical artifact statement; verified result record commits before release |
| `ROUTINE_TRANSITION_V1` | Nonce; persona/root/sequence/previous-head expectations; exact next public key and per-persona provider enrollment; migration flag fixed by state | Exactly one previous-key and one next-key SSHSIG over identical existing canonical transition bytes, both in `a-quo-persona-transition-v1`, tagged `previous` and `next`; atomic transition |
| `RECOVERY_PARTICIPATE_V1` | Nonce; sealed canonical recovery request; exact persona/root/policy/head/role expectations; participant provider enrollment | Every signature required of that participant by the existing purpose-separated recovery protocol; no persona authority change |
| Future `RECOVERY_POLICY_CHANGE_V1` | Nonce; exact current policy/continuity expectations; bounded proposed policy | All signatures required by the unchanged portable recovery-policy format, independently verified before one policy commit |
| Future `TERMINAL_REVOCATION_V1` | Nonce; exact root/current policy/head; bounded existing terminal statement | Complete authorized threshold signature set under existing terminal namespace; no successor signature; atomic permanent deauthorization and final receipt |
| `QUERY_RESULT_V1` / `CANCEL_V1` | Persona anchor, operation, caller nonce, complete request digest | No signer operation; exact state/result or closed cancellation outcome |

Every signing family includes the common tier, consent-profile, rollback and
expected-policy fields from §5.2 even where the table abbreviates them. Its
operation-specific root/head/recovery expectations remain mandatory. Protected
pins come from an authenticated enrollment or protected update; a caller's
claim that its own pin is independent does not establish provenance.

The first Tier 3 release need not implement every future message. An operation
not frozen and implemented as a closed method is unsupported, not routed to a
generic signer.

### 5.4 Authentication, limits, and closed outcomes

`SO_PEERCRED` and socket ownership identify an allowed local OS user for
partitioning, quotas, and audit, but do not identify an honest process within
that UID. Security instead comes from protected authority state,
persona-specific protected local consent, and the broker-only signer channel.
The authority authenticates the system-established consent endpoint and its
per-persona approval key, and validates the live protected ceremony on initial
acceptance. The signer authenticates only the fixed authority endpoint.
User-controlled buses and environment variables are not authority. A signed
local approval token supplies no independent history or rollback evidence.

Closed non-success outcomes include `InvalidRequest`,
`IdempotencyConflict`, `UnknownRequest`, `UnsupportedProtocol`,
`UnsupportedOperation`, `UnsupportedProvider`, `UnsupportedAssurancePolicy`,
`StaleState`,
`ConsentUnavailable`, `Declined`, `Cancelled`, `Expired`,
`RateLimited`, `SignerUnavailable`, `VerificationFailed`,
`CommitFailed`, `Indeterminate`, and `InternalFailure`. Details are
bounded enums plus safe field names; they never carry private material, raw
approval tokens, provider paths/endpoints, device/host IDs, or unescaped
attacker text.

Per-UID, per-persona, per-operation, global pending, protected-consent, and signer
quotas are checked before expensive work. Each stage has a bounded timeout and
an exact state-machine result. Protocol major, minimum security epoch, closed
message shape, and zero reserved fields are checked before consent or provider
access. A client disconnect is a cancellation request, not proof that a
provider or commit did not finish; section 8.3 governs the race.

## 6. Canonical signed material and AuthorityReceipt

### 6.1 Selected receipt model

This design selects **AUTHORITY RECEIPT BINDS CANONICAL SIGNED MATERIAL**.
There is no `FINALIZE_PROOF_V1` phase. This is sufficient because the Tier 3
claim concerns the exact statement, signatures, roles, persona, provider,
consent result, local policy/head expectations, assurance requirements and
committed outcome. Proof serialization, filenames, archive wrappers, QR layout
and output paths are outside that receipt's claim.

The authority never claims or signs a SHA-256 of final proof bytes. The final
proof does not exist when the authority constructs the receipt, and the
unprivileged builder remains responsible for its ordinary format.

### 6.2 Canonical encoding

`AuthoritySignedMaterialV1` is a strict RFC 8785 JSON object encoded as UTF-8.
Binary values use unpadded Base64url; digests use fixed lowercase hexadecimal;
integers must be exact JCS-safe integers; enums and identifiers are ASCII.
Duplicate keys, unknown fields, invalid UTF-8, noncanonical Base64url,
noncanonical JCS, excess nesting, and oversized values are rejected before
cryptography. Signature entries have operation-defined canonical role order;
callers cannot select or label roles or namespaces.

The tuple contains all security-relevant semantic material:

| Field | Required content |
|---|---|
| `schema`, `canonicalization`, `protocol_version` | `urn:a-quo:authority-signed-material:v1`, `RFC8785`, and the exact closed protocol |
| `operation_type`, `operation_result` | Closed operation and `signed`, `participated`, `committed`, or `terminally_revoked` as applicable |
| `portable_proof_schema`, `portable_proof_version` | Exact unchanged portable proof schema and version the builder must emit |
| `statement_schema`, `statement_purpose`, `statement_namespace` | Exact closed statement semantics; for multi-namespace recovery material, the exact role-to-namespace map |
| `canonical_statement` | The exact canonical statement bytes in Base64url, not only display text |
| `canonical_statement_digest` | Domain-separated SHA-256 of those exact bytes |
| `persona` | Persona anchor, pinned root-statement digest, and bounded self-asserted label |
| `persona_authority` | Per-persona authority key ID, authority-key epoch, and exact active enrollment-statement digest; never a service/host instance |
| `signatures` | Every required exact signature value, normalized public key, fingerprint, closed role, fixed namespace, and format/algorithm, in canonical role order |
| `providers` | For each signer role: per-persona provider-enrollment ID, admitted provider class, and public-key fingerprint; never endpoint, serial, account, or device certificate |
| `caller_nonce`, `complete_request_digest` | Exact 256-bit nonce and digest from section 5.2 |
| `consent_result_id` | Domain-separated SHA-256 of the canonical approval token; the raw token and its per-persona approval key remain local-only |
| `expected_state` | Exact locally accepted root, continuity head, recovery-policy head, lifecycle status, authority-key epoch, and policy generation used for the decision; no claim that this is the latest external state |
| `committed_state` | Exact resulting state/head/generation, or an explicit unchanged-state marker for non-state-changing operations |
| `assurance_tier` | Exactly `higher-assurance-v1`, with the local scope in §2.2 |
| `consent_profile` | Exactly `protected-local-v1`; must match the active enrollment, complete request and accepted consent |
| `rollback_requirement` | The effective request/protected-policy requirement; exactly `not_required` in this baseline; must match enrollment and consent |
| `receipt_sequence` | Ordered within this persona, authority-key epoch and retained result state; not an external monotonic counter or evidence that its own store was not restored |

Fields that are deliberately absent include final-proof digest or filename,
output path, service instance ID, host key, hostname, machine ID, OS account,
peer PID/UID, shared approval-device key/certificate, hardware serial/common
attestation chain, provider endpoint, exact service/build version, and raw
approval token. OS/distro/CPU names and exact driver/compositor versions also
remain outside portable material; they belong in local target qualification.

These are proposed, unimplemented authority formats; this revision changes no
released portable proof schema. All profile/requirement fields are mandatory
in the proposed v1 authority objects and are signature-covered. A bare
`witnessed`, `rollback_safe` or `fresh` flag, an untyped witness blob or a
local checkpoint is not a supported alternative encoding. A future stronger
profile must freeze its own complete evidence and verifier semantics before
it can be accepted.

For `ROUTINE_TRANSITION_V1`, `signatures` is unconditionally:

1. exactly one `previous` entry whose public-key fingerprint equals the
   statement's previous fingerprint; and
2. exactly one `next` entry whose public-key fingerprint equals the
   statement's next fingerprint.

Both verify over byte-identical canonical transition bytes in the existing
SSHSIG namespace `a-quo-persona-transition-v1`. The fixed proof-role tags
remain `previous` and `next`. Policy may add provider, hardware, consent,
expiry, or assurance restrictions; it can never remove either signature,
replace one with the authority signature, or create evidence rejected by the
unchanged portable verifier.

The current portable format separates these two authorities with the
`previous` and `next` role tags while requiring the same fixed
routine-transition SSHSIG namespace for both. This design preserves that exact
wire rule; it does not invent two new namespaces that the unchanged verifier
would reject.

### 6.3 Receipt envelope and signature

The material digest is:

```text
material_digest =
  SHA-256(
    "AQUO-AUTHORITY-SIGNED-MATERIAL-DIGEST-V1\0" ||
    canonical AuthoritySignedMaterialV1 bytes
  )
```

`AuthorityReceiptV1` is another strict canonical object containing only:

- `schema = urn:a-quo:authority-receipt:v1`;
- `protocol_version`;
- the persona anchor and root-statement digest;
- `authority_key_id` and `authority_key_epoch`;
- `receipt_sequence`;
- `material_digest_algorithm = sha256`;
- `material_digest`;
- `authority_signature_algorithm = ed25519`; and
- `authority_signature` over
  `"AQUO-AUTHORITY-RECEIPT-V1\\0" || canonical receipt preimage`.

The receipt is signed only by that persona's enrolled authority key. It is not
one of the persona-root, previous-key, next-key, recovery-authority, successor,
or artifact-signature roles.

The “receipt preimage” is the strict canonical object containing every listed
receipt field except `authority_signature`; the signature is then added once.
No digest or signature field is recursively included in itself.

### 6.4 Construction and atomic retention

After all operation signatures exist, the authority:

1. independently verifies every required signature, exact key, role,
   namespace, statement, persona, provider enrollment, accepted consent/profile/
   requirements, and current protected local policy/head;
2. constructs `AuthoritySignedMaterialV1` from verified values, never
   caller-authored proof output;
3. canonicalizes it, computes `material_digest`, and reparses/reverifies the
   complete tuple;
4. constructs and signs an unissued `AuthorityReceiptV1` candidate with the
   persona-specific authority key;
5. verifies its own receipt against the active enrollment;
6. immediately revalidates authoritative state; and
7. atomically commits the state transition if any, exact material bytes and
   digest, receipt, and terminal request result.

After commit it rereads and verifies the stored state, material, and receipt.
Only then may it return the statement, signatures, material, receipt, and
success. The proof builder subsequently creates the unchanged portable proof.
For artifact signing or recovery participation, the terminal result record
still commits only after all signatures and material have verified.

The precommit receipt candidate is not an issued success receipt: it is
unavailable outside the protected transaction, has no terminal-result record,
and is discarded if the commit fails. The atomic `Committed` transaction is
what issues it and makes its `operation_result` true. No failed operation
retains or releases a success receipt.

### 6.5 Offline verification algorithm

A receipt-aware verifier requires the artifact where applicable, portable
proof, signed material, receipt, persona authority enrollment chain, persona
root/continuity/recovery evidence, and verifier-owned root pin. It:

1. applies size/depth/count/duplicate/encoding bounds before cryptography;
2. parses and verifies the portable proof independently using the unchanged
   proof verifier, including its complete continuity/recovery chain rules;
3. verifies the root pin and the complete persona chain through the receipt's
   expected/committed head, establishing the receipt's historical position;
4. verifies the `AuthorityEnrollmentV1` chain, persona authorization,
   authority-key possession, persona/root match, key epoch, replacement and
   revocation status at the receipt sequence;
5. reconstructs a fresh canonical `AuthoritySignedMaterialV1`: proof-derived
   fields must equal independently verified proof semantics; receipt-only
   fields must obey the closed schema, enrollment and policy bindings. A nonce,
   consent digest or provider-class assertion is not thereby independently
   observed physical consent or provider qualification;
6. requires byte equality with the supplied canonical material, recomputes the
   domain-separated digest, and compares it to the receipt;
7. verifies the Ed25519 receipt signature with the enrolled per-persona
   authority key;
8. validates the consent profile and effective rollback requirement against
   enrollment and explicit verifier policy. Baseline evidence cannot satisfy a
   verifier requiring preventive rollback or fresh external authorization;
9. separately compares the supplied history with verifier-owned root, exact
   head and recovery-policy expectations, when present. A historical receipt
   may occur before the supplied history's current head: validate its issuance
   position first, then compare the relevant supplied history with the
   expected checkpoint. Do not require every historical receipt's issuance
   head to equal a later pin or let a valid receipt excuse a divergent history;
10. reports proof validity, receipt/enrollment validity, accepted local
    assurance claim and independent-history comparison as distinct results.
    Source independence and freshness are reported only to the extent actually
    established. A valid self-enrollment alone cannot qualify an installation.

The algorithm runs offline and never queries the authority service. Receipt
failure does not make a separately valid portable signature invalid; it
removes the Tier 3 authority claim and is reported distinctly. A baseline
receipt verifier rejects missing/unknown profiles or an asserted `required`
rollback property for the proposed baseline format; it never ignores critical
fields to display a stronger tier. An exact pin match still does not establish
that no newer history exists, and historical validity is not live permission
to invoke a signer.

For recovery participation before a threshold proof has been assembled, the
independently verified portable object is the existing canonical recovery
request plus the participant's purpose-separated response. If a completed
threshold proof is later supplied, it is also independently verified and the
participant material must occur in it exactly. Receipt verification never
requires the authority to assemble that proof.

## 7. Sign and verify before authoritative commit

### 7.1 Universal ordering invariant

Every new baseline signing operation, including one that leaves persona
history unchanged, follows this order:

1. Receive the caller-generated nonce and complete bounded request.
2. Validate the complete request, protected current state, enrollment/profile
   and effective requirements. Reject unsupported requirements before Pending.
3. Durably record only a non-authoritative `PendingRequest`.
4. Obtain protected local consent over the exact canonical statement,
   operation, nonce/request digest, state/provider expectations, consent profile
   and effective requirements. Durably accept its one-use decision.
5. Revalidate request, protected local policy, persona, provider enrollment,
   expected heads and accepted consent/requirements before signer access.
6. Invoke every mandatory signer through its role-specific closed operation.
7. Obtain the complete mandatory signature set.
8. Verify every signature against the exact canonical statement, required
   namespace, required role, registered public key, current persona, and
   policy state.
9. Construct, canonicalize, and verify the complete
   `AuthoritySignedMaterialV1` tuple and its receipt.
10. Revalidate authoritative state, accepted consent and requirements
    immediately before commit.
11. In one atomic compare-and-swap transaction commit the authoritative
    persona/policy/head/provider transition, exact verified material and
    digest, receipt, and terminal request result.
12. Reread and verify committed state, material, receipt and exact result.
    The baseline has no external checkpoint acknowledgement at this step.
13. Only then release any signature, portable proof inputs, receipt, or
    success.

The durable pending/request journal may reserve a nonce, store encrypted
pending key material, capture consent, or preserve provider retry state. It is
not persona authority. Before `Committed` it cannot create a root, advance a
head, activate or retire a signer, change policy/tier, terminally revoke a
persona, or activate a provider for subsequent persona operations. Pending
providers may perform only the exact enrollment/operation signatures already
specified for the consenting request.

If consent, provider access, signing, any signature verification, material
construction, receipt verification, final state comparison, or the atomic
commit fails, authoritative state remains unchanged. No success receipt,
partial proof, or raw signature is released. The request becomes a bounded
terminal failure or remains explicitly recoverable as `Pending` or
`Indeterminate`. Already produced signer output may be held only inside the
protected exact-result journal so retry never silently signs again.

### 7.2 Operation-specific ordering

| Operation | Pre-commit mandatory work | Single authoritative commit | Release |
|---|---|---|---|
| New persona root | Verify expected absence and exact protected pending per-persona enrollment; consent to root/enrollment; initial signer signs root and enrollment; authority key proves enrollment; verify root proof, enrollment, material, receipt | Create persona root, active signer/provider, policy/head, authority/approval enrollment, terminal request result | Root signature/proof inputs, enrollment, material, receipt |
| Artifact signing | Consent; current active signer signs; verify statement/signature/provider/material/receipt | No persona-state change; commit exact terminal result/material/receipt only | Signature/proof inputs and receipt |
| Routine transition | Consent; invoke previous then next (or safely parallel only if cancellation semantics remain exact); obtain exactly both; verify identical bytes, roles, namespace, keys, and complete resulting chain | Retire previous, activate next provider/key, append transition, advance head, commit material/receipt/result | Both signatures, transition proof inputs, receipt |
| Tier-2-to-Tier-3 migration | Verify existing full Tier 2 chain; enroll pending new provider/authority identities; Tier 3 consent; obtain migration-only old-key response and new Tier 3 signature; new key authorizes enrollment; verify complete resulting chain/material/receipt | Create Tier 3 protected state at the migration head, activate only new key/provider and authority enrollment; old key is never a Tier 3 provider | Dual-signed unchanged transition, enrollment, material, receipt |
| Recovery participation | Verify complete bounded recovery request and participant role; consent; obtain every participant response signature required by the existing protocol; verify response/material/receipt | No continuity/policy authority change; commit exact terminal participation result only | Participant response material and receipt; threshold proof assembly stays outside authority |
| Future recovery-policy change | Verify existing root, complete policy/transition chains, current thresholds and all old/current-policy role signatures; consent; verify proposed policy proof and material | Atomically append and activate exactly one policy version/head | Complete existing portable policy proof inputs and receipt |
| Future terminal revocation | Verify authorized policy capability, current root/head, exact terminal statement, complete threshold signature set, no successor, consent, material, and final receipt | Atomically append terminal proof, set zero active signers, freeze policy/continuity mutation, revoke Tier 3 enrollments, commit final result | Complete terminal proof inputs and final historical receipt |

Artifact signing and recovery participation commit result/receipt state without
advancing the persona continuity head. A separate history witness that records
only that head cannot detect loss or repetition of those results.

Recovery-policy change and terminal revocation are design constraints for later
closed operations, not authorization to implement them now. A future preventive
profile would need its own pre-sign external gate and distributed completion
rules (§2.4); adding an after-commit acknowledgement to this baseline sequence
would not by itself prevent signer use following a rollback.

## 8. Closed request state machine

### 8.1 State meanings

| State | Durable meaning | Authority/proof consequence |
|---|---|---|
| `Absent` | No nonce reservation exists for the tuple key | No authority, signer work, signature, proof, or receipt |
| `Pending` | Complete validated request digest and nonce are reserved | Non-authoritative; no consent or signer operation yet |
| `AwaitingConsent` | Exact canonical challenge, expected state, requirements and local protected-ceremony binding are retained | Still non-authoritative; no signer operation allowed |
| `AwaitingSignatures` | Exact local approval was durably accepted once; its validity and all state/provider/requirement facts were revalidated | Still non-authoritative; only the closed required signer calls are allowed |
| `SignaturesVerified` | The complete mandatory signature set and canonical material candidate have independently verified | Still non-authoritative; signatures remain protected and unreleased |
| `CommitInProgress` | A durable non-authoritative commit-intent marker exists and the final compare-and-swap is being resolved | No authority change has yet been reported; cancellation is too late to promise |
| `Committed` | One atomic transaction contains the new authoritative state if any, exact material/digest, receipt, and terminal request result | The only state that may create/change authority or expose success after reread |
| `Declined` | The exact consent request was declined | Terminal; no authority change, proof, receipt, or released signature |
| `Cancelled` | Cancellation won before commit | Terminal; no authority change or released material |
| `Expired` | An unapproved/abandoned request reached its bounded operational retention limit or its exact consent window ended | Terminal; no authority change or released material; nonce tombstone remains |
| `Failed` | A bounded, known failure occurred and non-commit is established | Terminal; no authority change or released material |
| `Indeterminate` | Provider outcome or storage state cannot yet be proven; automatic repetition would risk a second operation | No release; all Tier 3 work for the affected persona that depends on the uncertain fact is blocked pending closed reconciliation |

A `PendingRequest`, local consent decision, signer result or
`CommitInProgress` marker is never an authoritative persona state. Only
the atomic transaction that records `Committed` may activate it.

### 8.2 Transition table

“Durable write” below always means a write to the request/result journal, not
persona authority, unless the row explicitly says it is the atomic
`Committed` transaction.

| From → to | Trigger and preconditions | Durable writes | Authority changes? | Allowed signer work | Exact retry | Cancellation | Crash result | Proof/receipt availability |
|---|---|---|---|---|---|---|---|---|
| `Absent → Pending` | `SUBMIT_*_V1`; nonce unused; complete bounded request, sealed input, expected state, digest and supported requirements valid | Reserve tuple key, full digest, safe request facts, and state `Pending` | No | None | Same digest returns `Pending`; different digest conflicts | May immediately win to `Cancelled` | Record is absent or wholly `Pending` | None |
| `Pending → AwaitingConsent` | Worker claims request; current state still equals expectations; exact challenge constructed | Challenge digest, requirements and local protected-ceremony binding, state | No | None | Returns/resumes the same request; invalidated ceremonies fail closed | Wins before valid approval is accepted | Resume only a provably valid protected ceremony or fail known-safe | None |
| `AwaitingConsent → Declined` | Protected consent service returns an authenticated decline for the exact nonce/request/challenge | Terminal decline and safe consent-result digest | No | None | Same decline | Already terminal | Same decline | None |
| `Pending/AwaitingConsent → Cancelled` | Exact `CANCEL_V1` wins state CAS before approval acceptance | Terminal cancel and safe audit code | No | None | Same cancellation | Already terminal | Same cancellation | None |
| `Pending/AwaitingConsent → Expired` | Exact consent window or configured abandonment interval ends before signer work | Terminal expiry and permanent nonce/digest tombstone; bulky input may be compacted | No | None | Same expiry | Terminal | Same expiry | None |
| `AwaitingConsent → AwaitingSignatures` | Local token signature, persona consent enrollment, nonce/RD, operation, statement digest, expiry, policy/head, requirements and protected ceremony all verify; authority revalidation and one-use acceptance succeed | Protected accepted-approval record sufficient for exact verification, consent-result digest and state; acknowledge acceptance to the guard; raw token is never logged/exported and may be discarded after terminalization | No | Only all mandatory role-specific calls for this request | Resumes from accepted consent only while its exact validity and protected policy remain established | May request cancellation; it wins only before commit CAS | Reconcile accepted consent and exact required signer set; no generic re-sign | None |
| `AwaitingConsent → Failed` | Consent unavailable/expired/invalid, or post-consent revalidation is known to fail | Closed terminal failure and safe digest | No | None | Same failure | Terminal | Same failure | None |
| `AwaitingSignatures → AwaitingSignatures` | One of several required signer results is durably recorded and verified, but the set is incomplete | Exact protected signer result/digest and remaining-role bitmap | No | Only missing mandatory roles; never repeat a recorded successful role | Reuses recorded result | If cancel wins, no further role is invoked; completed output stays unreleased | Resume missing role or become `Indeterminate` if provider outcome unknown | None |
| `AwaitingSignatures → SignaturesVerified` | Every mandatory signature exists and verifies against exact bytes, roles, namespaces, keys, persona, provider, and state; complete chain and material verify | Complete protected signature set, canonical material/digest, verified receipt candidate facts, state | No | None | Reuses exact verified set; no new signing | Can win before commit-intent CAS, producing `Cancelled` and no release | Resume final state comparison; no re-sign | None |
| `AwaitingSignatures → Cancelled` | Cancellation wins the request CAS and every invoked provider outcome is known; no commit intent exists | Terminal cancel, per-role outcome digests, no exported signature | No | No remaining role may be invoked | Same cancellation | Already terminal | Same cancellation | None |
| `AwaitingSignatures → Failed` | Provider gives a known failure or any signer/signature/material check fails; non-commit established | Terminal failure; safe provider/result digest, never private data | No | None | Same failure | Terminal | Same failure | None |
| `AwaitingSignatures → Indeterminate` | Provider may have acted but no exact result/non-result can be established | Indeterminate marker, role, provider operation digest | No | No further signer call | Query/reconcile only | Returns `too_late_or_indeterminate` | Remains indeterminate | None |
| `SignaturesVerified → CommitInProgress` | Final local policy/persona/provider/head/consent/requirement revalidation succeeds; commit lock/CAS acquired | Non-authoritative commit-intent marker | No | None | Query same commit resolution | Too late to promise cancellation; returns `commit_in_progress` | Recovery inspects atomic transaction; never assumes | None |
| `SignaturesVerified → Cancelled` | Cancellation wins the one CAS before commit intent | Terminal cancel; protected signature outputs remain unreleased and are not authority | No | None | Same cancellation | Already terminal | Same cancellation | None |
| `SignaturesVerified → Failed` | Final comparison is stale or receipt/material self-verification fails before commit | Terminal known non-commit failure | No | None | Same failure | Terminal | Same failure | None |
| `CommitInProgress → Committed` | Atomic compare-and-swap succeeds with exact expected old state and already verified complete material | In one transaction: authority delta, material bytes/digest, receipt, exact terminal result, state `Committed` | **Yes; this is the only row** | None | Returns exact stored result | Too late; returns committed result/status | Atomic recovery observes wholly old or wholly committed state | Retained; release waits for committed-state/material/result reread and verification |
| `CommitInProgress → Failed` | Atomic transaction definitely did not commit and unchanged authority is verified | Terminal failure/non-commit marker | No | None | Same failure | Terminal | Same failure | None |
| `CommitInProgress → Indeterminate` | Storage corruption or external provider journal prevents proving committed versus not committed | Indeterminate safety marker in independent recovery metadata where possible | Never intentionally; service treats affected authority as frozen until resolved | None | Query/recovery only | Too late/indeterminate | Remains blocked | None |
| `Committed → Committed` | Reread/query/retry; stored historical commit, exact result, material, receipt and enrollment evidence verify | Delivery-attempt metadata only; no semantic result change | No new change | None | Byte-identical terminal result; no consent/signing/mutation | `too_late` plus exact committed status | Remains committed | Released after verified reread; no fresh consent, witness or signer operation |
| `Indeterminate → AwaitingSignatures/SignaturesVerified` | Closed provider query proves the exact prior outcome and returns either a known non-operation or the exact signature for this tuple/role | Reconciliation evidence and resolved state; never a new provider call merely because status was unknown | No | Only still-missing roles after non-operation is proven and policy permits; never repeat a proven operation | Continues same request | Normal rule for resolved state | Returns to indeterminate if durable resolution is lost | None |
| `Indeterminate → Committed` | Recovery proves the exact atomic transaction already committed | Repair request-state view to the already committed terminal record; no new authority write | No new change | None | Exact committed result | Too late | Remains committed | Available only after full committed-result reread and verification |
| `Indeterminate → Failed` | Recovery proves no commit and a known terminal provider/non-provider outcome | Terminal reconciliation evidence | No | None | Same failure | Terminal | Same failure | None |
| `Declined/Cancelled/Expired/Failed → same state` | Query or identical retry | Delivery/audit metadata only | No | None | Same exact terminal disposition | Already terminal | Same terminal state | None |
| Any nonterminal → `Failed` | Known bounded parser, policy, provider, verification, timeout, or storage failure with established non-commit | Terminal safe failure | No | None after transition | Same failure | Terminal | Same failure | None |
| Any nonterminal → `Indeterminate` | The service cannot safely establish whether an external signer acted or the commit completed | Indeterminate marker and safe reconciliation facts | No new intentional change | None until resolved | Closed query only | Indeterminate | Remains blocked | None |

For an atomic local database transaction, restart recovery must normally resolve
`CommitInProgress` by reading the transaction: either authority is wholly old
or the exact request is wholly `Committed`. `Indeterminate` is reserved for
genuine corruption or an external provider whose result cannot be queried; it
is not a routine substitute for correct transactions.

The local ceremony has a separate protected acceptance handshake. The guard
retains protected presentation/input ownership through the user's decision and
the acceptance exchange. The authority verifies the decision's authenticated
ceremony binding, serializes it against cancellation/expiry and durably accepts
it at most once before acknowledging that acceptance. A token received from a
desktop relay or a different/invalidated ceremony cannot enter
`AwaitingSignatures`.

A normal guard teardown after accepted consent does not revoke that already
accepted exact decision. If the handshake is interrupted, reconcile the
protected acceptance record: an accepted valid decision may resume the same
request, while a decision whose valid acceptance cannot be established permits
no new signer call. Unknown consent alone, with no signer invocation, is a
known-safe failure rather than a provider `Indeterminate`. Raw token replay
never creates a second acceptance or a new request. Validity after restart
must be established from protected records and the defined expiry rules;
an old token's signature alone is insufficient.

This handshake records local consent, not an independent history checkpoint.
After a request reaches `Committed`, result delivery needs only verified
historical commit/result evidence. Loss of the response or later consent-UI
availability cannot require another approval, another signature or a new
authority transition.

### 8.3 Cancellation races

| Race point | Required result |
|---|---|
| Before any signature | Cancellation may win the request-state CAS and produce terminal `Cancelled`; no signer is invoked |
| During a provider operation | Record `cancel_requested`; attempt provider cancellation. If cancellation wins before a verified complete set and commit intent, do not invoke remaining signers, do not commit, and never release any completed signature. If provider outcome is unknown, use `Indeterminate`, not a retry. |
| Complete signatures, commit not begun | Cancellation and commit-intent compete on one CAS. Cancellation winner yields `Cancelled`; commit-intent winner returns `commit_in_progress` and cancellation cannot promise success. |
| Commit in progress | Return `commit_in_progress` or `Indeterminate`; never report cancelled until known. Resolve the atomic transaction. |
| Commit completed, response lost | Cancellation is too late. Query/retry returns the exact committed result without consent, signer work, or mutation. |

## 9. Corrected operation sequences

All sequences below use `N` for the caller nonce, `RD` for the complete
request digest, `AK(P)` for the persona-specific authority key, and `AR`
for the AuthorityReceipt. “Return” always occurs after verification of the
committed state and exact retained result/material/receipt. There is no
baseline external checkpoint confirmation.

Every sequence includes §5.2's common requirements in the request and digest,
checks them against protected policy before Pending, displays them in the
§11.3 local ceremony, and binds the effective values in accepted consent and
material. The baseline never admits `required` rollback prevention. Existing
operation-specific root/head/recovery-policy pins remain mandatory; a pin
match does not establish that no newer history exists.

### 9.1 New Tier 3 persona root

1. A fresh 256-bit persona anchor and the exact proposed signer, `AK(P)`,
   consent enrollment and provider IDs are prepared through the protected
   non-authoritative enrollment step (§4.3). The caller then durably saves
   fresh `N` and the complete bounded root request with expected absence.
2. The authority validates uniqueness, provider qualification, distinct
   per-persona keys, exact public keys, enrollment/requirements and bounds;
   computes `RD`; and writes only `Pending`. All proposed identities and
   policy remain inactive and cannot be replaced after digest reservation.
3. It constructs the unchanged canonical persona-root statement and canonical
   `AuthorityEnrollmentV1` statement. The protected consent service
   authenticates `AK(P)` through the system-established per-persona channel,
   shows root, key, authority enrollment, Tier 3 claim and limitations,
   `N`, `RD` and expected absence, and returns exact local consent.
4. The authority verifies consent and revalidates absence/provider/pending-key
   uniqueness.
5. The initial Tier 3 signer signs the root under
   `a-quo-persona-root-v1` and signs the enrollment statement under
   `a-quo-authority-enrollment-v1`. `AK(P)` signs enrollment possession.
6. The authority verifies all three signatures, the complete root proof,
   enrollment binding, exact roles/namespaces/keys, and policy.
7. It constructs and verifies signed material, signs/verifies AR with
   `AK(P)`, and immediately revalidates expected absence.
8. One atomic transaction creates the authoritative root, active signer and
   provider, policy/head, authority/approval enrollment, exact material/AR,
   and committed result.
9. It rereads and verifies the root, enrollment, exact result, material and
   receipt. Only then are root proof inputs, enrollment, material and AR
   returned for unprivileged proof construction.
10. If the response is lost, query with anchor, operation, `N`, and `RD`
    returns the exact result. It never creates a second root or signs again.

### 9.2 Tier 3 artifact signing

1. Before submission the caller persists fresh `N`, opens the artifact
   without following a mutable path, creates a sealed snapshot, and submits it
   with persona, kind, label, provider, root/policy/head expectations.
2. The authority validates seals, size, provider/state, independently hashes
   the complete bytes, constructs the existing canonical artifact statement,
   computes `RD`, and records only `Pending`.
3. The protected consent service displays the authenticated exact digest,
   size, kind, label, persona, purpose, provider fingerprint/class, policy/head,
   `N` and `RD`;
   its per-persona local approval token binds them.
4. The authority verifies consent and revalidates all request, persona,
   policy/head, and provider facts.
5. The current Tier 3 signer signs the exact canonical artifact statement in
   its existing fixed namespace. The authority verifies the SSHSIG against the
   registered current key and statement.
6. It constructs/verifies signed material and AR, then atomically commits only
   the terminal result/material/receipt; persona authority is unchanged.
7. It rereads/verifies the committed result and returns proof inputs and AR.
   The unprivileged builder creates the unchanged artifact proof and
   independently verifies it before publication.
8. Lost response/exact retry returns the byte-identical committed result and
   performs no consent, signer, or state operation.

### 9.3 Routine Tier 3 transition

1. The caller persists fresh `N` and submits exact persona/root/sequence/
   previous-head expectations plus the already pending, distinct, qualified
   next per-persona provider/public key. The caller supplies neither statement
   bytes, signature roles, nor namespaces.
2. The authority fully verifies the current root and complete chain, reads the
   active previous key/provider, constructs the unchanged canonical routine
   transition statement, computes `RD`, and records only `Pending`.
3. The protected consent service displays both fingerprints, exact root/head/sequence, provider
   changes, statement digest, `N`, `RD`, and that both signatures are
   mandatory. Its approval token binds the exact transition.
4. The authority verifies consent and revalidates current head, policy,
   previous/next providers, key distinctness, and enrollment.
5. The previous provider makes exactly the `previous` SSHSIG and the next
   provider makes exactly the `next` SSHSIG. Both cover byte-identical
   canonical statement bytes under `a-quo-persona-transition-v1`.
6. The authority requires exactly those two role entries, verifies both keys,
   signatures, roles, fixed namespace, statement, and the complete resulting
   chain. No policy can waive either.
7. It constructs/verifies signed material and AR, then immediately repeats the
   current-state comparison.
8. One atomic transaction appends the proof material, retires the old signer,
   activates the new signer/provider, advances the head, and commits the
   result/material/receipt.
9. It rereads and reverifies the complete chain/state/material/AR, then returns
   both signatures and receipt for unchanged portable-proof construction.
10. A lost response with the same `N`/`RD` returns the existing transition.
    A new nonce against the old head is stale and cannot create a sibling or
    second transition silently.

### 9.4 Explicit Tier-2-to-Tier-3 migration

1. The caller persists fresh `N` and provides the independently pinned root,
   complete existing portable continuity/recovery chain, exact current Tier 2
   signer public key, and a pending new qualified Tier 3 provider/public key.
   Fresh per-persona authority/consent/provider enrollment is already prepared
   but inactive; the submitted request fixes those exact proposed values.
2. The authority independently verifies the full chain and current root/head/
   key, rejects ambiguous or invalid evidence, constructs the exact next
   existing `ROUTINE_TRANSITION_V1` statement, computes `RD`, and records
   only `Pending`.
3. The protected Tier 3 consent service displays the old Tier 2 status, both fingerprints,
   complete head, assurance upgrade, new authority enrollment, exact statement
   digest, migration operation, `N`, and `RD`; it signs exact consent.
4. After consent and revalidation, the authority issues a
   `MIGRATION_PREVIOUS_SIGNATURE_CHALLENGE_V1` naming only this pending tuple:
   exact transition bytes/digest, old public key/fingerprint, fixed
   `previous` role, fixed `a-quo-persona-transition-v1` namespace, root,
   head, operation, `N`, and `RD`.
5. The unprivileged coordinator may relay that challenge only to the future
   migration-specific operation at the existing Tier 2 consent/signer
   boundary. That closed path shows the exact old-key authorization and
   returns one SSHSIG response. There is no generic signature-submission
   method and the authority never accepts a caller-selected key, statement,
   role, or namespace.
6. The authority accepts `SUBMIT_MIGRATION_PREVIOUS_SIGNATURE_V1` only for
   the live pending challenge and verifies the SSHSIG over the exact stored
   bytes with the exact current old key, `previous` role, fixed namespace,
   root/head, `N`, and `RD`. The nonce is bound by the challenge, approval,
   request, and signed material; it is not added to the unchanged portable
   transition statement.
7. The new qualified Tier 3 provider creates the mandatory `next` SSHSIG over
   the same transition bytes. It also signs the per-persona authority
   enrollment statement; `AK(P)` signs enrollment possession.
8. The authority verifies both transition signatures, exact roles/namespace,
   old and new keys, new provider enrollment, authority enrollment, user
   consent, migration nonce, and the complete resulting chain.
9. It constructs/verifies signed material and AR and revalidates the verified
   source-chain expectations plus the absence of a Tier 3 persona record.
10. One atomic transaction creates protected Tier 3 state at the accepted
    transition, activates only the new provider/signer and per-persona
    authority enrollment, records material/AR/result, and leaves no Tier 3
    enrollment for the old key.
11. After committed-state/result reread and verification, the dual-signed
    unchanged transition, enrollment, material and AR are released for proof
    building.
12. Failure or interruption before commit leaves the Tier 2 persona and old
    key state unchanged and creates no Tier 3 proof/receipt. Exact retry cannot
    create a second transition; response loss after commit returns the exact
    first result.

The previous signature proves only that the old key signed the exact migration
transition. It cannot prove which same-user process reached that Tier 2 key;
that limitation is explicit and is why pre-migration history is not relabelled.

### 9.5 Recovery participation

1. The coordinator persists fresh `N` and supplies one sealed, bounded,
   canonical recovery-ceremony request with exact root, policy, transition
   head, participant role, and per-persona provider enrollment expectations.
2. The authority uses only the operation-specific bounded parser, fully
   verifies the portable root/policy/transition evidence and participant role,
   computes `RD`, and records only `Pending`. It does not parse an archive
   or build a threshold proof.
3. The protected consent service shows the participant identity within the persona, exact request
   and transition digests, role, proposed successor, policy/head, `N`, and
   `RD`, then returns exact consent.
4. After revalidation, the enrolled participant provider produces every
   purpose-separated signature required of that participant by the existing
   recovery protocol, including its exact request binding where required.
5. The authority verifies all participant signatures, roles, namespaces,
   keys, exact statements, request binding, expiry policy, and current
   expectations; then constructs/verifies signed material and AR.
6. One atomic transaction commits only the exact participation
   result/material/receipt. It does not change continuity head, recovery
   policy, active signer, or authority tier.
7. After committed-result reread and verification, the response and AR may be
   released.
   Threshold assembly, general proof parsing, recovery activation, and any
   later state commit stay outside this operation.
8. Lost response/retry returns the same participation response; it never asks
   the participant key to sign again.

### 9.6 Terminal query and exact retry

1. The caller uses its already saved persona anchor, operation, `N`, and
   `RD`; it never needs an authority-created request ID.
2. The authority performs a constant-shape bounded lookup of that tuple.
3. Unknown tuple returns `UnknownRequest`; known nonce with wrong `RD`
   returns `IdempotencyConflict`; pending states return the exact closed
   status and permitted next action.
4. `Committed` triggers no consent or signer operation. The authority
   rereads/reverifies the historical committed state and exact result/material/
   AR, and completes response delivery. A later policy change, unavailable
   consent UI or unavailable external witness does not turn retrieval into a
   new operation or a claim of fresh authorization.
5. `Declined`, `Cancelled`, `Expired`, or `Failed` returns the same
   terminal disposition. `Indeterminate` exposes only its operation-specific
   reconciliation action.
6. A response lost after commit is therefore observationally identical to an
   exact committed retry, while a changed request with the same nonce can
   never be mistaken for it.

## 10. Migration choice and continuity invariants

This design selects option **B: one explicit reviewed migration from an
existing Tier 2 persona**. It is valid only when the existing active key is
available for the mandatory previous-key signature or an already authorized
recovery route produces the existing recovery transition instead. It is not an
“adopt this database” operation.

The migration invariants are:

- The authority verifies a verifier-pinned root and complete portable chain
  before constructing the transition. A user SQLite database and a hash stored
  beside it are advisory, not independent tamper evidence.
- The portable migration is an ordinary existing
  `ROUTINE_TRANSITION_V1`, containing exactly one `previous` and one
  `next` signature over identical canonical bytes in the fixed existing
  namespace. The unchanged portable verifier must accept it.
- The previous Tier 2 key is used only for the previous role through the
  migration-specific bridge. It is never enrolled as a Tier 3 provider.
- The next key is a separately enrolled qualified Tier 3 provider and cannot
  become active until both transition signatures, complete resulting chain,
  authority enrollment, material, receipt, and final state comparison verify.
- Protected local Tier 3 consent covers the exact transition, migration nonce,
  old/new keys, accepted head, provider enrollment, authority enrollment,
  consent profile, effective requirements and assurance upgrade. The existing Tier 2 path separately consents to old-key use.
- Root-pinned validity alone does not prove the source chain is latest. The
  protected enrollment procedure establishes which independently obtained
  expectations are being accepted, enforces any required exact-head/policy
  pins, and reports their provenance/freshness limits. It cannot satisfy a
  requirement for unavailable fresh external evidence by labelling a caller's
  own archive independent. Baseline Tier 3 starts from that explicitly
  accepted local state; it does not promise to discover every withheld fork.
- Historical root, policy, transition, consent, database, and signer evidence
  remains Tier 2. Tier 3 starts at the accepted migration transition only.
- Migration says nothing retroactive about resistance of the old key, old
  consent path, old database, or previous history to same-user malware.
- Failure, cancellation, or interruption before commit leaves the previous
  operational Tier 2 state unchanged. Pending identities and signatures are
  not active and are not released.
- One atomic compare-and-swap commit makes exactly one transition. Exact retry
  returns it; a second request against the old head is stale.
- If the previous active key is gone, A Quo does not invent routine
  continuity. It verifies and uses an already authorized recovery route, or
  requires a new persona with exact nonclaims.
- If known prior key reuse or exported common attestation already links
  persona histories, migration cannot erase that fact. The ordinary Tier 3
  privacy profile refuses to add or carry a new shared authority identity and
  reports the historical privacy limitation rather than promising anonymity.

## 11. Provider, consent, state-loss and platform lifecycle

### 11.1 Provider admission

| Provider | Tier 2 | Baseline Tier 3 | Reason/condition |
|---|---|---|---|
| User-owned OpenSSH private-key file, encrypted or not | Yes | No | Desktop malware can copy, replace or invoke it; passphrase unlock is not isolated consent |
| Ordinary desktop SSH agent | Yes | No | Same-user processes can use its socket directly |
| Desktop-accessible FIDO stub/device | Yes | No | Touch/UV is not exact-statement consent and the channel is directly reachable |
| Dedicated service-only agent | Conditional | Only after qualification | Endpoint and keys unavailable to desktop UID; closed per-persona slot; exact protected local consent; no shared portable identity |
| Service-exclusive FIDO/hardware key | Conditional | Only after qualification | Per-persona signing key, exclusive endpoint, qualified protected local consent and no exported common attestation |
| Trusted-display hardware signer | Conditional | Only after qualification | Meets the same exclusive-provider requirements and local consent profile; a device-display-only alternative needs a separately specified consent profile |
| Platform keystore/vendor signing service | Conditional | Only after qualification | Service-only access, exact closed requests, per-persona identity, queryable outcomes and protected local consent |
| Official identity wallet | Presentation only | Not an A Quo signing provider | Credential presentation stays in its own protocol and custody model |

A provider class in signed material is an assertion by the enrolled persona
authority, not manufacturer attestation. Each provider must demonstrate the
required exclusivity, per-role result journal/query behaviour, persona
separation and consent enforcement. A touch, PIN or user-verification flag may
unlock a qualified provider but cannot replace exact request consent.

These are admission conditions, not a claim that every listed provider already
implements the closed protocol. An unqualified provider is ineligible for the
requested Tier 3 operation; any Tier 2 use is a separate explicit request.

### 11.2 Downgrade and state loss

- Protected state retains the minimum accepted protocol/schema/security epoch,
  enrollment, consent profile and persona policy. Missing or older values,
  stale request expectations and known mismatches fail before new signer work.
- These are local checks against retained state. A coherent restoration of all
  protected software, policy, enrollment and journals is excluded by baseline
  §2.2; local counters cannot detect their own restoration. A desktop-accessible
  mechanism for performing such a restore fails baseline isolation.
- CLI and service require an explicit requested tier and expose the achieved
  profile/requirements. Missing consent, authority or provider support never
  redirects a Tier 3 request to the desktop daemon. A separately consented
  Tier 2 request uses a new nonce and produces only Tier 2 evidence.
- A Tier 2 proof cannot acquire Tier 3 status by adding an after-the-fact receipt:
  the authority did not consent to, validate and commit that exact request.
- Unsupported strengthening, including `rollback_requirement = required`,
  fails before Pending/consent/signing. Retained protected policy cannot be
  weakened by a request. A future preventive profile must also resist restoring
  an earlier unprotected policy at its external signer-enforcement boundary.
- Response loss uses exact committed-result query. It is not state loss.
  A historical result remains queryable without a new physical ceremony or
  freshness claim, including after a later transition or terminal revocation.
- Known protected-state loss, restore or corruption freezes affected new
  signing. User-owned archives/mirrors and locally adjacent hashes do not
  reconstruct authority automatically. Reconciliation must establish retained
  state and exact provider outcomes under a qualified closed recovery path.
  If that cannot be established, use an already authorized recovery route or
  a new persona; do not invent continuity.
- A lost signer permits routine replacement only if the previous key can
  supply its mandatory signature. Otherwise use existing authorized recovery
  or a new persona. Consent/enrollment loss follows §4.3.
- Portable proofs and historical receipts remain verifiable after service
  loss when their public evidence is retained. They supply no fresh guarantee
  that no later revocation or competing history exists.

### 11.3 Protected local consent ceremony

This is the selected general Linux `protected-local-v1` ceremony. A browser
or phone is not involved. Implementations may use different qualified Linux
supervisors, drivers and nested desktops; the following properties are fixed.

1. **Trusted startup and custody.** A system-installed supervisor starts the
   protected outer compositor, consent service, authority and signer with
   separate service identities and fixed authenticated connections. Their
   binaries, libraries, configuration, environment, state and runtime endpoints
   are not desktop-writable. No desktop plugin, startup hook, session bus or
   arbitrary executable selection can become protected code. Privileged setup
   opens/assigns only the required devices; steady-state services remain
   non-root with bounded access.
2. **Physical ownership.** The guard retains the physical display/input path
   from trusted startup onward. The ordinary desktop is a nested client. It
   receives only authorized rendering access and forwarded ordinary input;
   it cannot open physical KMS/input, inject into enrolled devices, create
   accepted virtual devices or regain control through a seat manager or
   root-equivalent API. Old inherited FDs and device reopens are part of this
   test. Merely grabbing evdev or changing device permissions after an
   untrusted session started is insufficient.
3. **Protected attention.** A reserved gesture from an enrolled physical
   device is consumed by the outer guard, regardless of desktop focus,
   inhibition, grabs or workload. It is not forwarded as approval input.
   The user invokes this protected entry for signing; resemblance to the
   consent screen is never its authentication. A nested fake screen or a
   synthesized key sequence cannot open an accepted ceremony.
4. **Complete presentation.** On entry the guard suppresses untrusted content
   on every relevant output, plane and cursor. It uses protected, unshared
   buffers and rendering resources and does not wait on an untrusted client
   fence to acquire the consent view. Screen capture, remote control, overlay,
   clipboard and accessibility facilities exposed to the desktop cannot
   observe/control the protected scene or return approval. Output hotplug,
   suspend, VT/device loss and guard failure follow a closed abort or
   revalidation path. They must never reveal a still-actionable prompt under
   hostile content.
5. **Exact authenticated facts.** The consent service authenticates the fixed
   authority endpoint and the local per-persona enrollment. It displays the
   authority-canonical statement or every field needed to reconstruct its
   semantics: persona/root, purpose, artifact digest/size where applicable,
   operation/result intent, roles, key fingerprints, provider class,
   policy/head, authority enrollment where applicable, nonce/request digest
   and effective assurance requirements. Names are explicitly self-asserted.
   It describes the local-consent guarantee and separate history/rollback
   limits in understandable language. The authority supplies bounded derived
   facts; arbitrary files, archives, markup or scripts are not rendered.
6. **Deliberate physical decision.** Entry waits for a neutral release state
   so a held key/button, autorepeat, stale input or the attention chord cannot
   approve. The complete required information must be accessible before a
   separate physical approval gesture is enabled. Decline/cancel are explicit.
   Focus/navigation failure, clipping that prevents disclosure, ambiguous
   device provenance, expired challenge or incomplete display fails closed.
   Showing a digest establishes which bytes are authorized, not that those
   bytes are safe or fully understood.
7. **Exact local token and acceptance.** The consent service signs a closed,
   bounded token with `approval_key_P`, binding persona/root, local
   enrollment, operation, nonce/RD, canonical statement digest(s), exact
   policy/head/provider expectations, consent profile, effective requirements,
   decision, expiry and a fresh per-ceremony protected-instance challenge.
   Multi-statement enrollment/recovery operations bind every mandatory
   statement. The instance is local and request-specific, never a host ID.
   The authority validates and durably consumes this decision once through
   §8.2's authenticated acceptance handshake before any signer call. Raw
   tokens are never logged or exported.
8. **Lifecycle and expiry.** Ceremony, decision, cancellation, invalidation
   and acknowledgement have serialized transitions over the protected local
   protocol. A final decision must be made while its exact display/input
   binding is valid. Invalidating an unfinished ceremony cannot race a late
   token into new authority. An accepted decision may outlive normal UI
   teardown only for its exact request and validity window. A protected
   elapsed-time source controls local deadlines; wall-clock timestamps are
   not trusted freshness evidence. If restart or suspend handling cannot
   establish the acceptance and remaining validity, no further signer call
   is allowed. Completed or uncertain provider calls are reconciled, never
   repeated merely to obtain a new consent.
9. **Accessibility.** Qualified keyboard navigation and visual disclosure are
   required. Where speech or other assistive output is needed, that path must
   be protected too: desktop-controlled audio cannot spoof, mix over or
   suppress required disclosure while the operation still succeeds. Assistive
   navigation/approval inputs must meet the same physical provenance and exact
   decision rules, or the configuration is unsupported. Ordinary desktop
   accessibility and audio services are not approval authority.

This token authenticates a protected local ceremony under trusted system
assumptions. The consent key, its counters and its acceptance records are in
the same machine rollback domain. None is an independent witness, secure
clock, hardware attestation or proof of whole-machine rollback resistance.

### 11.4 Installation, upgrade, replacement and uninstall lifecycle

| Event | Required behavior |
|---|---|
| Initial installation | Administrator/package manager creates static service identities, protected binaries/configuration, narrow state/runtime directories, fixed authenticated sockets, guard-first session startup and exclusive device/provider access. Runtime services are non-root. Installation alone creates no Tier 3 persona. |
| Target qualification | Record the actual Linux kernel/driver/input/display/session/provider combination and verify §§3.5, 11.3 and 12.4. Distribution names or available kernel APIs alone cannot enable the Tier 3 claim. Local qualification records are not copied into persona receipts. |
| Persona enrollment | Protected local per-persona binding and inactive key preparation follow §4.3. Exact signing/activation needs the consented operation and atomic commit. User SQLite is only a mirror after verified commit. |
| Tier 2 coexistence | Existing daemon/socket/store remain the explicit `trusted-desktop` tier. Tier 3 has a distinct closed endpoint and explicit requirements; no automatic routing between them. |
| Old client | Missing nonce, tier/profile/requirements, epoch, exact state or closed fields is rejected before consent. Desktop clients have no direct signer/provider access. |
| Authority software/state-schema upgrade | Verify old protected state before a durable epoch change. Persona security-policy/profile/enrollment changes use their explicit protected lifecycle; packaging alone cannot rewrite a signed persona enrollment. Qualify changed isolation/driver/protocol assumptions before enabling the affected profile. |
| Authority-key/service replacement | Planned replacement uses the same-persona enrollment transition in §4.3 and protected local consent. It does not copy a common host key into personas. |
| Consent-service replacement | Preserve verified per-persona consent custody and authenticated connections, or use the qualified protected reenrollment path. An untrusted UI, copied token or ordinary daemon cannot replace the service. |
| Signer replacement | Ordinary dual-signed transition or existing authorized recovery only; user database paths and provider stubs are not authority. |
| Crash/restart/stale endpoint | System supervision establishes correct owners, modes and peer identities. User-created endpoints are rejected. Protected request/result/provider journals resolve exact work as §8 specifies. |
| Deliberate downgrade or known restore | Retained minimum epochs and mismatch/restore detection block new signing. A coherent restore of every local enforcement record remains the baseline nonclaim. An administrator reset is an explicit recovery/discontinuity decision, never silently a continuation. |
| Uninstall | Administrator-controlled shutdown preserves or deliberately exports only non-secret public roots, proofs, enrollment/revocation evidence, material, receipts and pins. Private authority/signer/consent keys and recovery secrets are never exported as a convenience. |
| Reinstall with retained state | Verify protected state, key custody, enrollment, policy/schema epochs and complete result/provider journals. Resume only under a qualified reconciliation path; known restored backups cannot silently replace missing authority. |
| Complete protected-state loss | Portable verification continues; new Tier 3 signing stops. An already authorized recovery route or a new persona is required if the closed retained-state recovery path cannot establish authority. |

### 11.5 General Linux 0.x scope and dependencies

The service/session implementation target is **general Linux**, with qualified
deployment profiles. Linux credentials, private sockets, process/filesystem
isolation, physical-device ownership and a protected outer display/input owner
are the requirements. systemd/udev is the first reference supervision/device
setup; equivalent arrangements can qualify. Hyprland is the first inspected
nested desktop, not the only permitted compositor. Asahi/Apple ARM supplies
one inspected driver/device topology, not a normative dependency.

This requires A Quo integration, session/device-policy changes and qualification
using existing interfaces. It does not require browser mediation or waiting
for an upstream Linux secure-consent feature. It is not a claim that stock
desktop sessions, all distributions or every graphics driver already qualify.
Failure on a target results in an explicit unsupported profile, not weaker
consent under the same label.

Portable proofs, enrollment, signed material and receipt verification are
platform-independent data/cryptography. A macOS or Windows protected signing
implementation could be specified separately; their service, keystore and
physical-consent paths are not defined or claimed by this Linux design.

Future work coordinates with issue #2 for continuity/history and pending
witness work, #4 for threshold recovery, #6 for consent accessibility, #20 and
#24 for official identity-wallet presentation handoff, #25 for portable Linux
release, and #69 for the installed Tier 2 journey. Independent history
comparison uses the existing semantics; unfinished witness infrastructure is
not a baseline implementation dependency. Any preventive extension requires
the separate qualification in §2.4.

Issues #57 and #65 and merged gpgv work do not define or continue this
authority design. Plug & Prejudice remains the behavioural plugin-analysis
owner.

### 11.6 Consolidated nonclaims

No proof, receipt, enrollment, provider class or baseline tier label
establishes:

- resistance to administrator/root-equivalent, kernel, protected guard,
  consent/authority service, signer-provider or relevant firmware compromise;
- detection or prevention of coherent whole-machine restoration of all local
  protected state, including local consent, nonce/result and epoch records;
- that ordinary continuity-head witnessing covers artifact-signing result
  loss, or that a post-sign checkpoint prevented an earlier signer invocation;
- authenticated loaders/libraries, reproducible/source/build provenance or
  remote attestation of installation qualification;
- secure attention on unqualified Linux sessions or unspecified macOS/Windows
  implementations;
- physical-coercion resistance, availability, freedom from prompt spam or
  recovery after loss of every authorized key/state/recovery route;
- legal/organizational identity, artifact/content truth or safety, user
  understanding of arbitrary content, trusted time, independent witnessing
  or global freshness;
- absence of a newer/withheld competing persona history or revocation when
  fresh, separately obtained evidence is unavailable;
- anonymity against external data, timing/content correlation, network
  observation, external key reuse or colluding recipients;
- A Quo custody of official-wallet credentials, or persona signing keys outside
  their explicitly selected provider custody; or
- cryptocurrency/blockchain transaction signing or wallet authority beyond
  separately designed official identity-wallet presentations.

## 12. Positive and hostile validation plan

### 12.1 Required positive AuthorityReceipt vectors

Each fixture contains exact canonical bytes and expected digests/signatures.
“Retained evidence” is public proof material or bounded non-secret audit data;
raw approval tokens and provider diagnostics stay protected. These are future
acceptance requirements, not tests implemented or run by this design revision.
Every baseline success fixture uses `protected-local-v1` and `not_required`.

| Vector | Exact input | Expected result and verification stage | Authority state change | Retained evidence |
|---|---|---|---|---|
| New Tier 3 persona | Fresh anchor, distinct initial signer, `AK(P)`, approval key, provider enrollment, nonce, valid root/enrollment signatures and AR | Success through structural checks, portable root verification, enrollment/receipt verification, and Tier 3 policy evaluation | One atomic root/persona commit | Root proof, enrollment, material, AR, exact terminal result |
| Ordinary artifact signing | Fixed artifact bytes plus current persona/root/policy/head/provider, fresh nonce, valid signer output and AR | Success: artifact proof verifies first; reconstructed material and receipt then verify | Persona authority unchanged; one terminal result commit | Artifact proof, material, AR, request/result record |
| Valid two-key routine transition | Exact canonical transition with one `previous` and one `next` SSHSIG under `a-quo-persona-transition-v1`, fresh nonce | Success through complete portable chain, receipt, and policy evaluation | Exactly one head/provider transition commit | Dual-signed transition proof, material, AR, new head |
| Accepted Tier-2-to-Tier-3 migration | Verified Tier 2 prefix, migration challenge response from current old key, new qualified key response, new per-persona enrollment, fresh nonce | Success; old prefix remains labelled Tier 2 and Tier 3 begins at migration transition | Exactly one atomic Tier 3 activation at new head | Full prefix, migration proof, enrollment, material, AR |
| Exact committed retry | Repeat identical persona/operation/nonce/request digest and body after commit | Success at query/idempotency evaluation; byte-identical result, no new cryptography | None | Existing terminal result plus retry audit code |
| Response lost after commit | Drop first response after committed-state reread, then query using saved tuple | Success after verified committed-result reread; no external checkpoint exchange or re-sign | None after first commit | Existing exact material/AR/result and delivery audit |
| Independent receipt verification | Move artifact/proof/material/AR/enrollment/root pin to an offline verifier with no authority socket | Success: portable proof first, then enrollment/material/receipt and policy | None | Offline verification report with claims separated |
| Two personas on one machine | Create two fixtures with distinct anchors, signer keys, authority keys, approval keys, provider IDs and nonces; compare every exported field | Success at privacy-policy evaluation: no stable installation/device/authority value is equal by construction except public protocol constants | Two independent persona commits | Both public fixture sets and a field-by-field correlation report |
| Historical receipt before planned authority replacement | Receipt sequence below old key's signed replacement cutoff plus complete same-persona replacement chain | Success as historical receipt during enrollment/receipt policy evaluation | None | Old receipt, replacement enrollment, cutoff evidence |
| Recovery participation | Valid bounded recovery request and all purpose-separated participant response signatures plus AR | Success through recovery response, receipt, and policy evaluation | Persona authority unchanged; terminal participation result only | Participant response, material, AR |

### 12.2 Mandatory negative AuthorityReceipt and privacy vectors

| Vector | Exact input change | Expected result and failure stage | Authority state changes | Retained evidence |
|---|---|---|---|---|
| Forged authority signature | Flip one bit of `authority_signature` while material and enrollment remain valid | Reject during receipt cryptographic verification | None | Safe `InvalidAuthoritySignature` code and receipt digest |
| Unknown authority algorithm | Replace `ed25519` with `ed448` or numeric unknown value | Reject before cryptography as a closed-enum/schema error | None | Safe `UnsupportedAuthorityAlgorithm` code |
| Wrong persona-specific authority key | Verify persona A's receipt signature with persona B's enrolled public key | Reject during enrollment/receipt verification | None | Persona/root and key-ID mismatch code |
| Receipt from persona A presented as B | Pair A's unchanged material/AR with B's proof, root pin, or report persona | Portable proof may verify for B, but reject during material/enrollment/receipt verification before Tier 3 policy succeeds | None | Cross-persona mismatch code and both public digests |
| Two receipts accidentally use the same authority key | Attempt to enroll the identical authority public key/ID for persona B after persona A and construct A/B receipt fixtures with that key | Reject B during precommit policy evaluation; an offline corpus that observes both also rejects B's Tier 3 enrollment/receipt relationship | None | Duplicate-key safe audit record; no accepted common-key enrollment or B receipt emitted |
| Revoked authority key | Present a receipt sequence after that key's persona-local revocation cutoff | Signature may be cryptographically valid; reject during enrollment/revocation policy evaluation | None | Revocation evidence and `AuthorityKeyRevoked` |
| Replaced authority key | Sign a new post-cutoff receipt with the old key after a valid replacement | Reject during enrollment epoch/sequence policy evaluation; pre-cutoff historical fixture remains valid | None | Replacement chain and cutoff mismatch |
| Replaced enrollment proof | Swap the valid enrollment object for another persona/key while leaving receipt unchanged | Reject during enrollment/receipt verification | None | Enrollment digest/key mismatch |
| Incorrect enrollment pin | Supply a different verifier-owned root digest or persona anchor | Reject during portable persona-chain/enrollment verification | None | Pin mismatch report |
| Forged persona enrollment authorization | Alter the persona SSHSIG on `AuthorityEnrollmentV1` | Reject during enrollment cryptographic verification | None | Invalid enrollment signature code |
| Host-wide authority identifier leakage | Add `authority_instance_id`, machine ID, hostname, or broker key to material, receipt, enrollment, QR fixture, or report | Reject before cryptography as a prohibited/unknown critical field; release test fails | None | Field name and safe schema error, never its sensitive value |
| Shared device certificate leakage | Add a device serial, common approval key, AAGUID-like unique value, manufacturer certificate, or common attestation chain | Reject before cryptography under the ordinary portable profile | None | Prohibited-field code |
| Altered material digest | Flip one bit of receipt `material_digest` | Reject during receipt signature/digest verification | None | Expected/observed digest mismatch |
| Altered statement bytes | Flip one byte in the portable proof payload, leaving signatures/AR | Reject during portable proof verification before receipt trust | None | Portable statement/signature failure |
| Altered purpose | Change `statement_purpose` only in signed material | Portable proof still checked independently; reject during material reconstruction/receipt digest verification | None | Semantic-field mismatch |
| Altered namespace | Change a material/proof signature namespace to an artifact or root namespace | Reject during portable proof verification when proof changed; otherwise during reconstructed-material/receipt verification | None | Namespace/role mismatch |
| Altered signer public key | Replace one proof signature's public key with another normalized public key | Reject during portable proof fingerprint/signature verification | None | Key/fingerprint mismatch |
| Altered signer fingerprint | Change a statement or material fingerprint without changing the key | Reject during portable proof verification if in statement; otherwise receipt material reconstruction | None | Fingerprint mismatch |
| Altered previous-key signature | Flip one bit in the `previous` SSHSIG | Reject during portable routine-transition verification | None | Previous-role signature failure |
| Altered next-key signature | Flip one bit in the `next` SSHSIG | Reject during portable routine-transition verification | None | Next-role signature failure |
| Removed required signature | Delete either routine-transition signature | Reject during portable proof structural/cryptographic verification; authority precommit test also never reaches commit | None | Missing-role code |
| Duplicated signature role | Replace `next` with a second `previous` entry | Reject during portable proof structural verification before receipt cryptography | None | Duplicate/missing-role code |
| Reordered signature roles | Swap the signed material's entries from canonical `previous,next` order without changing their tags or receipt | Base portable semantics are checked first; sidecar canonical-order/material comparison rejects during receipt verification | None | Noncanonical role-order code |
| Mislabelled signature role | Relabel old-key signature as `next` and new-key signature as `previous` | Reject during portable role-to-fingerprint/signature verification | None | Role/key mismatch |
| Substituted approval token | Replace protected raw token after consent and before signer invocation; leave request fixed | Reject during authority consent cryptographic/binding evaluation before any signer work; no receipt is constructed | None | Safe consent failure and token digest only |
| Approval token for another request | Submit a valid token whose nonce/RD/challenge names another pending request | Reject during precommit consent policy evaluation before signer work | None | Request-binding mismatch |
| Changed consented statement digest | Alter challenge statement digest after protected local approval | Reject during consent binding/revalidation before signer work; if only material changes later, receipt reconstruction rejects | None | Consented-versus-current digest mismatch |
| Changed request nonce | Present an accepted token, material or query under a different nonce while retaining old RD/AR | Reject the consent/request binding before signer work or the material/receipt binding offline; query returns unknown/conflict according to its exact tuple | None | Original tuple record and conflict code |
| Nonce reused across personas | Submit persona B with persona A's already accepted nonce, even with a different operation/body | Reject during precommit nonce/privacy policy evaluation; no B reservation, consent, signer work, or portable evidence | None | Safe cross-persona nonce-reuse code |
| Changed operation type | Reuse nonce/receipt as another closed operation | Reject before work as tuple/digest conflict or during material/receipt verification offline | None | Operation mismatch |
| Changed persona | Change anchor/root in request/material while reusing nonce/receipt | Reject during request policy or enrollment/receipt verification | None | Persona mismatch; no foreign state disclosed |
| Changed policy or continuity head | Increment, decrement, or substitute expected policy/head | Reject during precommit state policy evaluation; offline material alteration rejects receipt digest | None | Stale-state or material mismatch |
| Changed assurance tier | Replace `higher-assurance-v1` with `trusted-desktop` or unknown tier | Reject during material/receipt verification and tier policy evaluation | None | Tier mismatch |
| Missing/changed consent profile | Omit `consent_profile`, substitute an external-device profile, or disagree with the signed enrollment | Reject schema/enrollment/consent/material binding as applicable; do not infer a default | None | Profile mismatch or unsupported-profile code |
| Changed rollback requirement | Alter `not_required` to `required`, strip the field, or change requested/effective requirements after consent | Reject schema or exact request/consent/material binding; baseline cannot issue stronger material even with otherwise valid signatures | None | Requirement mismatch/unsupported-policy code |
| Self-declared freshness | Add `witnessed`, `rollback_safe`, a local-counter freshness flag or an untyped external-evidence blob | Reject unsupported critical semantics; no stronger claim is displayed | None | Closed-field or unsupported-claim code |
| Software identity in portable material | Add distro, CPU/driver build, exact compositor version or shared installation qualification ID | Reject outside the portable profile; qualification stays local | None | Prohibited/unknown-field code |
| Changed signer-provider identity | Substitute another per-persona provider ID/class while keeping key/signature | Reject during provider policy/material reconstruction | None | Provider-enrollment mismatch |
| Changed terminal result | Replace `committed` with `signed`, `failed`, or another result | Reject during material/receipt digest verification | None | Terminal-result mismatch |
| Receipt/proof semantic mismatch | Combine a valid artifact proof with AR/material from a different valid artifact request | Portable proof succeeds; reject during reconstructed-material/receipt verification | None | Both public digests and mismatch code |
| Forbidden proof-file digest claim | Add `proof_file_sha256` to receipt/material or make a report say AR attests serialized proof bytes | Reject field before cryptography; report-policy test rejects the unsupported claim | None | Prohibited-field or unsupported-claim code |
| Replay against another persona | Reuse unchanged AR/material/enrollment with another persona's root/proof | Reject during enrollment/receipt verification | None | Cross-persona replay code |
| Replay against another operation | Reuse artifact AR for transition or recovery evidence | Reject during material/receipt verification | None | Operation replay code |
| Replay against another policy state | Reuse old AR/material as authorization for a later head/policy operation | Historical receipt may verify, but reject during current-operation policy evaluation; it authorizes no new commit | None | Stale expected-state report |
| Stale protocol version | Decrement protocol version or use an unsupported epoch | Reject before cryptography on input; offline verifier reports unsupported protocol before receipt trust | None | Version error |
| Unknown critical field | Insert `critical_future_semantics` anywhere in a strict object | Reject before cryptography | None | Unknown-field code |
| Duplicate field | Encode two `material_digest`, `persona`, or `role` keys | Reject before canonicalization/cryptography | None | Duplicate-field code |
| Oversized receipt | Exceed the frozen receipt or nested-field byte/count bound by one byte/entry | Reject before allocation-intensive work or cryptography | None | Size-limit code and length only |
| Truncated receipt | Remove each possible terminal byte in corpus cases | Reject during bounded parse before cryptography | None | Truncation code |
| Noncanonical encoding | Add JSON whitespace, use padded Base64url, alternate escape, unsafe integer, or non-JCS key order | Reject canonical-byte equality before cryptography | None | Noncanonical-encoding code |
| Parser control-character attack | Inject raw NUL/newline/ESC into a closed identifier or unescaped JSON string | Reject before cryptography; diagnostic escapes untrusted text | None | Safe field/code only |
| Unicode display attack | Insert bidi override, noncharacter, confusable control, or invalid UTF-8 into receipt metadata; separately alter a valid statement label | Invalid metadata rejects before cryptography; valid statement text is byte-bound and safely escaped, and alteration rejects in portable proof verification | None | Safe-display or proof mismatch code |
| Invalid time/expiry | Expire the approval token before signer work, regress an existing statement time, or violate an explicit provider-policy interval | Reject during consent/policy evaluation or portable proof time-rule verification as applicable; never infer trusted time | None | Closed expiry/time-policy code |
| Cross-persona exported-field correlation | Scan two complete ordinary portable bundles and deliberately inject each local installation/device field in turn | Clean fixtures succeed with no deterministic shared value; every injected prohibited field rejects before receipt trust | None beyond the two valid persona commits | Field inventory, equality analysis, and prohibited-field results |

The reordered-role rule applies to the canonical signed-material projection.
The unchanged portable verifier defines proof semantics. A different valid
serialization of the ordinary portable proof with identical semantic material
must retain receipt validity. Noncanonical sidecar bytes or a different signed
role projection fail the stricter authority-material check. This distinction
tests that the receipt does not accidentally bind a final proof-file layout.

### 12.3 State, retry, commit-order, and boundary vectors

| Vector | Exact fault/input | Expected result and stage | Authority state changes | Retained evidence |
|---|---|---|---|---|
| Commit before signatures fault | Inject a commit attempt in every state before `SignaturesVerified` and with one routine role missing | Reject at state-policy evaluation; storage invariant prevents authority write | None | State-transition violation |
| Invalid signature before commit | Provider returns wrong-key or wrong-byte signature | Reject during signature/portable-material verification; no AR success | None | Safe provider-result digest |
| Final head changes | Concurrently commit another valid transition immediately before target CAS | Target rejects stale state during final policy/CAS evaluation | Only the competing authorized commit | Target terminal stale-state record |
| Commit write failure | Fault each write/fsync/transaction boundary | Either wholly unchanged `Failed` or wholly `Committed`; never partial authority | None or the one exact commit | Fault point and post-restart invariant report |
| Reread mismatch | Corrupt test store after atomic commit but before release | No release; freeze affected persona and report `Indeterminate` during postcommit verification | The prior atomic commit may exist; no second change | Corruption/recovery evidence |
| Same nonce/same request pending | Disconnect after durable `Pending`, then resubmit exact body | Resume same request at idempotency evaluation | None until its one eventual commit | One tuple record |
| Same nonce/different request | Change one field or sealed-input byte with same persona/op/nonce | `IdempotencyConflict` before consent/signing/mutation | None | Original digest and safe conflict |
| Caller loses first response | Disconnect immediately after first send at every journal point; caller retains nonce/body | Query locates exactly the original request without authority-generated ID | At most one exact commit | One tuple/result |
| Abandoned pending GC | Let a no-signer pending request exceed configured interval, compact payload, then retry nonce | Same terminal `Expired`; nonce never becomes reusable | None | Permanent tuple/digest tombstone |
| Cancellation before signature | Cancel in `Pending` and `AwaitingConsent` | Terminal `Cancelled` at state-policy evaluation | None | Cancel record |
| Cancellation during provider | Block provider, send cancel, then test provider success/failure/unknown outcome | No commit or release when cancel wins; unknown becomes `Indeterminate`; no second call | None | Cancel race and provider outcome digest |
| Cancellation after signatures | Race cancel against commit-intent CAS | Exactly one winner: `Cancelled` with no commit or commit proceeds | None or one exact commit | CAS outcome |
| Cancellation during commit | Cancel after `CommitInProgress` | Too late/unknown until transaction resolution; never false `Cancelled` | None or one exact commit | Resolved transaction state |
| Response lost after commit | Drop all response bytes after committed reread | Query returns byte-identical result; no signer or consent call | No additional change | Digest equality and call counters |
| Crash after each signer role | Kill before invocation, during provider call, after result journal, and after verification | Resume only known missing role; unknown provider outcome becomes `Indeterminate`; never silently repeat | None | Per-role exact-result journal |
| Pending described as authority | Attempt artifact signing or transition using an inactive pending root/key/provider | Reject at authority-state policy evaluation | None | Inactive-object code |
| Optional routine signature policy | Configure policy claiming previous or next signature optional | Reject policy at validation; no operation starts | None | Invalid-policy code |
| Authority receipt as continuity role | Put AR signature into `previous` or `next` slot | Reject during portable proof verification | None | Role/format mismatch |
| Generic signer method | Send caller-chosen bytes, namespace, key path, role, or command | Reject structural schema before provider access | None | Closed-method rejection |
| Mutable locator substitution | Change user DB path, agent socket, or provider stub after request | Tier 3 revalidation ignores/rejects it; enrolled service slot remains exact | None | Provider-enrollment result |
| Tier 3 dependency absent | Remove protected guard/consent service, authority or exclusive provider and submit a new Tier 3 signing request | Fail closed at policy/availability evaluation; no Tier 2 call | None | Explicit Tier 3 failure |
| User DB rollback | Restore an older user SQLite mirror while protected authority/result state remains current | Requests naming older expectations fail against protected state; the mirror cannot restore authority | None | State/head mismatch or correct protected result |
| Known protected-state restore | Announce a backup restore, remove required records, or restore one component while retained protected journals expose a mismatch | Freeze affected new signing; reconcile only through the closed recovery path | None | Known-restore/missing-state/mismatch evidence |
| Desktop-reachable protected restore | Attempt protected store/epoch/journal replacement through every installed filesystem, container or administrative API available to the desktop UID | Access must be denied; otherwise target fails baseline qualification | None in a passing target | Boundary failure or access-denial evidence |
| Local hash as witness | Offer only a hash/pin stored beside the same restorable database as independent evidence | No independent-history or preventive-rollback claim; any policy requiring such evidence remains unsatisfied | None | Provenance limitation or unsupported requirement |
| Shared attestation provider | Qualify hardware whose only export includes one stable device certificate for all personas | Reject ordinary portable Tier 3 profile during provider/privacy evaluation or keep attestation local-only | None | Qualification decision without certificate export |
| Proof-builder compromise | Builder alters fields, omits a signature, or emits different proof after authority return | Independent proof or receipt verification rejects; authority is never asked to parse/output it | None | Invalid output and committed source material |
| Parser/fuzz boundary | Mutate every receipt/enrollment/material byte and cross all size/count limits | Bounded precrypto rejection or specific proof/receipt failure; no crash/unbounded allocation | None | Sanitized corpus outcome and coverage |

### 12.4 Required general Linux protected-consent qualification

These tests qualify each advertised kernel/driver/session/provider combination.
They must use the actual protected path and hostile desktop UID, not only a
headless compositor or simulated successful token.

| Vector | Setup/attack | Required baseline outcome and evidence |
|---|---|---|
| Physical entry and decision | Genuine enrolled keyboard, reserved attention gesture, exact prompt, separate approval | One exact accepted decision; provider/commit counters show the one specified operation |
| Fake prompt and synthetic input | Nested lookalike, input replay, held keys, autorepeat, virtual keyboard, uinput/ydotool, writable evdev/hidraw/usbfs or remote-control attempts | No accepted consent from synthetic/unqualified paths; neutral-entry barrier and explicit physical decision tested |
| Hostile desktop presentation | Overlays, fullscreen, pointer locks, shortcut inhibitors, client crash/hang, busy render fences, secondary output and cursor manipulation | Physical attention works and required protected facts remain uncontaminated; otherwise abort with no signer call |
| Protected capture and buffer isolation | Desktop screenshots, screencopy, remote desktop, clipboard/accessibility APIs, shared GPU buffers and device reopening | Desktop cannot capture/control protected consent or map its buffers through authorized interfaces; any bypass fails target qualification |
| Guard lifetime | Lose display/input, hotplug output, switch VT, suspend/resume, kill guard/renderer at each unfinished ceremony boundary | No acceptance of invalidated unfinished consent; no desktop content under an actionable protected prompt; exact known failure/reconciliation |
| Acceptance/acknowledgement races | Race physical decision, cancellation, expiry, invalidation, durable acceptance and lost acknowledgement | At most one valid accepted decision; unknown pre-sign consent fails safely; accepted exact consent follows defined validity/recovery rules |
| Accepted consent replay | Replay raw token for same/different request, persona or guard instance; restart before each signer role | No second acceptance; no role repeated; new signer calls only from established accepted consent with valid state/deadline |
| Protected service boundary | Forge socket/path/peer, edit binaries/config/environment, use D-Bus calls, access protected home/state or signer agent | Desktop cannot select protected code, write authority state or reach signer/consent authority |
| Privilege/device escape | Existing FDs, logind/seatd-equivalent grants, container sockets, input groups, credential or administrative paths available without separately trusted action | No path to physical devices, protected processes or root-equivalent control; offending configurations are unsupported until corrected |
| Provider outcomes | Timeout/disconnect at each provider phase and after each role | Exact prior result query or explicit Indeterminate; no re-sign because the result was lost |
| Accessibility | Keyboard-only navigation, long/escaped labels, multiple outputs, required assistive input/output and hostile desktop audio | All required facts are accessible through protected channels; no hidden field, ambiguous approval or desktop-authoritative assistive path |
| General Linux portability | Run the same invariant suite for each claimed target, including a non-Asahi target before advertising tested non-Asahi support | Same protocol/profile/receipt semantics; only local qualification details differ. Asahi names/versions never become portable trust requirements |
| Upgrade and known restore | Change relevant driver/service/configuration, downgrade retained epochs, restore known backup or omit state | Requalify changed boundaries; reject known stale/missing state before new signing; no claim to detect restoration of every local check |
| Query without UI or witness | Commit, then stop consent UI and any unrelated history service before exact query | Byte-identical historical result after verified reread; zero consent, signer or authority-changing calls |

Independent security review remains a release prerequisite. This definition
does not claim that the current Asahi session, another Linux target or any
provider has passed these tests.

### 12.5 Independent history and claim-separation vectors

| Vector | Exact evidence/condition | Required result |
|---|---|---|
| Root-only historical prefix | Valid older chain and independent root pin, no head expectation | Existing proof validity may succeed; no latest-history or rollback-prevention claim |
| Exact head mismatch | Valid prefix or sibling plus separately retained later/different expected head | Exact-checkpoint verification fails; local receipt validity cannot override it |
| Matching checkpoint | Valid chain whose effective head equals the supplied exact pin | Match relative to that pin; report source/freshness limitations and no absence-of-newer-history guarantee |
| Archive relationships | Exact match, extension beyond a pin, divergence at/before it and shorter candidate | Preserve existing exact/extension/divergence/shorter-inconclusive semantics; neither longest nor matching extension automatically acquires authority |
| Recovery-policy expectation | Valid history with a policy that differs from the independently expected policy or explicit absence | Report the applicable policy mismatch; continuity-head agreement alone is insufficient |
| Terminal effective head | Valid terminal leaf plus otherwise matching prior prefix | Respect existing effective-head/terminal rules; do not report the retired signer active from an earlier receipt |
| Restored or self-supplied pin | Pin copied from the candidate archive or restored with the same machine | Consistency may be evaluated; independence and fresh witnessing are not established |
| Old but independent pin | Independent source supplies a checkpoint with unknown or insufficient freshness | Report its provenance and limited relationship; cannot satisfy a policy requiring unavailable fresh authorization |
| Historical receipt in later history | Valid receipt issued before a later independently pinned head, both in one valid supplied chain | Verify historical issuance position and compare the supplied history separately; receipt need not claim issuance at the later head |
| Local result loss with same head | Artifact-signing result differs/is lost while continuity head remains identical | Head comparison cannot establish result/nonce/receipt completeness or prevent duplicate signer use |
| Offline baseline receipt | Valid enrollment/material/receipt under `protected-local-v1`, `not_required` | Report the accepted local authority assertion separately; do not infer actual installation qualification, independent history or live authorization from its signature |
| Entire machine coherently restored | All local policy, consent, counters and journals restored together under a controlled fault harness | Baseline promises no detection/prevention. Report this excluded scope; a co-restored local hash is not a successful detector |

The core exact-checkpoint and archive-comparison semantics already exist
(§2.3). These vectors also specify future authority/report integration; they
do not imply the pending witness publication/freshness work is implemented.

### 12.6 Stronger requirement admission and future extension gates

The first three rows are **mandatory baseline** refusal/reporting tests.
The remaining rows are obligations for a separately specified preventive
profile, not a phone/witness dependency for baseline release.

| Scope | Vector | Required result |
|---|---|---|
| Baseline | Request/enroll `rollback_requirement = required`, including otherwise valid exact consent/provider facts | `UnsupportedAssurancePolicy` before Pending acceptance, consent or signer work; no fallback |
| Baseline | Strip/lower effective requirements, disagree with protected policy/enrollment or change requirements after digest reservation | Reject schema, policy or exact binding before the next security-relevant step; no weaker receipt |
| Baseline | Offline verifier requires prevention/fresh authorization but is supplied only valid baseline evidence or a self-declared witness flag | Ordinary proof may remain valid; required stronger assurance fails explicitly |
| Future profile | Restore stale local policy/software, including a pre-enrollment `not_required` image, while external enforcement retains newer state | Gated signer refuses bypass before any new invocation under stale relevant state |
| Future profile | Reuse an old signed witness response, wrong nonce/RD/role, expired grant, different persona or conflicting operation | Authenticated gate rejects before signer use according to its precise freshness/serialization rules |
| Future profile | Two concurrent fork proposals or requests against one state | No unauthorized double advancement; no accepted authority before complete signatures and verification |
| Future profile | Restore result/receipt/nonce state while retaining the same continuity head | Prevent the duplicate-use condition actually promised by that profile; head-only evidence must fail qualification for that promise |
| Future profile | Crash after reservation, before/after each signer role, around local commit and external completion; lose every reply in turn | Recover exact outcomes without new unauthorized signer work; state the distributed availability/Indeterminate limits |
| Future profile | Lose witness connection or substitute a local hash/post-sign acknowledgement | Required gate remains unavailable; no skip, downgrade or false prevention claim |
| Future profile | Reenroll/recover/revoke witness or signer policy; compare two personas' exported evidence | Authenticated lifecycle cannot reopen stale signer authority or add a common persona identifier; report observer/traffic limits |

No witness/hardware protocol is selected by merely listing these tests.
A future extension must define the actual messages, durable states,
enforcement custody, recovery and verifier evidence before qualification.

## 13. Implementation decomposition

These are future, bounded work items. The current task defines the design and
does not implement services or create issues/PRs.

1. **Freeze the closed baseline contracts and enrollment lifecycle.**
   Finalize the proposed enrollment/material/receipt formats, protected pending
   key preparation, persona-specific consent binding, protocol bounds,
   request/effective requirements, nonce retention, cancellation, acceptance
   and recovery states. Preserve the unchanged portable formats, mandatory
   signature roles and privacy exclusions. An unsupported stronger requirement
   must fail before Pending.
2. **Build and qualify the general Linux protected-consent path.**
   Implement the guard-first session, nested desktop integration, fixed
   protected services, physical attention, exact accessible presentation,
   local token and acceptance handshake. Qualify actual device/process/GPU
   boundaries on each target; keep Asahi/Hyprland/systemd integration details
   outside the protocol. Existing kernel interfaces are the implementation
   basis, not an assumption of future upstream consent support.
3. **Qualify exclusive signer providers and exact outcome recovery.**
   Implement only the role-specific per-persona slots, authenticated authority
   channel, protected provider journal and closed result queries. Demonstrate
   denial of desktop access and handling of unknown outcomes. This depends on
   the contracts in item 1 and integrates with item 2's consent boundary.
4. **Implement the authority's verified atomic operations.**
   Compose exact accepted consent, local state enforcement, mandatory signer
   orchestration, post-sign verification, canonical material/receipt, final
   CAS and reread-before-release. Cover every applicable §12.3 crash/race
   point. Pending records and provider reservations never become persona
   authority early.
5. **Implement offline authority evidence and separate history reporting.**
   Add bounded authority-object parsing, unchanged-proof-first verification,
   enrollment/policy trust evaluation, semantic reconstruction and separate
   local/history/stronger-requirement results. Use the existing continuity
   comparison semantics; do not invent a witness service or freshness claim.
   Exercise tampering, valid proof reserialization and two-persona privacy.
6. **Implement explicit Tier-2-to-Tier-3 migration.**
   Add only the exact previous-role challenge bridge, qualified next-key
   signature, new authority enrollment and one atomic activation. Preserve
   pre-migration Tier 2 status and exact retry. Depends on items 1–5.
7. **Qualify installed lifecycle, accessibility and adversarial operation.**
   Test package/startup permissions, supported system/driver/provider targets,
   known state loss/restore, upgrades, recovery, historical queries, all
   applicable §12 vectors and independent security review. Issue #6 contributes
   accessibility work. Passing issue #69's Tier 2 journey cannot satisfy this
   baseline gate.
8. **Separately design any required preventive rollback profile.**
   Select and specify the external enforcement boundary, complete state
   coverage, pre-sign authorization, distributed completion/recovery, privacy
   and verifier evidence described in §§2.4 and 12.6. This is an optional
   workstream; unfinished witness infrastructure cannot hold up qualification
   of the local baseline. Until qualified, `required` stays unsupported.

Items 1–7 define the baseline implementation path. Target/provider
qualification failures must be resolved before advertising that combination;
they cannot be deferred by weakening the common assurance claim.

## 14. Decision record and remaining engineering choices

The owner selected the assurance separation on 2026-09-05 and clarified that
the design must cover general Linux rather than an Asahi-specific workaround.
This revision defines that direction. It does not record implementation
completion or independent security approval.

| Defined decision | Result |
|---|---|
| Baseline assurance | `higher-assurance-v1` with `protected-local-v1`, protected locally accepted state and exclusive signer access |
| Consent implementation direction | System-owned outer display/input guard, nested untrusted desktop and separate protected native consent service |
| Required hardware/software | A qualified Linux physical display/input path and exclusive provider; no mandatory browser, phone, Asahi/Apple device or future upstream Linux feature |
| Whole-machine rollback | Not a baseline promise. Issued baseline enrollment/material requires `not_required`; a request/policy requiring prevention is unsupported before Pending/signing |
| Independent history | Separate checkpoint/policy comparison with explicit provenance/freshness limits; existing comparison is usable and witness publication/freshness remains separate work |
| General Linux support | One common security contract; each advertised kernel/driver/session/provider target qualifies against it. Asahi is the inspected reference target |
| Authority and identity | Separate protected service state; unrelated per-persona authority/consent/signer/provider identities; no portable installation identity |
| Consent and result ordering | Exact request → non-authoritative Pending → protected one-use consent → every mandatory signature → full verification/material/receipt → final CAS → atomic commit → verified reread → release |
| Receipt meaning | Canonical semantic signed material, including profile and requirements; no final proof-file digest or post-build finalize phase |
| Routine transition and migration | Exactly previous + next signatures over unchanged canonical transition bytes; explicit migration activates Tier 3 only at its new head |
| Retry | Caller-saved nonce and complete digest recover one exact result; committed query requires no new consent, signer use or external checkpoint |
| State loss | Known loss/restore freezes affected new signing; user mirrors cannot silently restore authority; historical proof verification remains available |
| Failure reporting | No silent tier/profile/policy downgrade; local assertion, history comparison and stronger requirements have distinct outcomes |

Engineering choices still need to be frozen and qualified during the bounded
implementation work. These include the outer compositor/rendering library,
per-target nested backend and device policy, reserved physical gesture and
accessible disclosure, the first exclusive signer provider, exact protected
enrollment/reenrollment and recovery messages, timeout/quota constants,
historical-evidence retention UX, and the initial closed operation set.
Unsupported operations or recovery paths remain unavailable until specified.

The baseline defines one active protected consent enrollment per persona.
Multiple approvers, approval thresholds, a device-only consent alternative
and manufacturer-attestation profiles are future extensions, not implicit
requirements or permission to weaken this profile. A qualified recovery path
may replace an enrollment explicitly; an administrator reset may not silently
invent continuity.

The separate product question of cryptocurrency/blockchain transaction signing
is unchanged. Current wallet scope remains official identity-wallet
presentation; issue #68 does not expand it.

## 15. Review findings and assurance decisions

| Finding | Severity | Original defect | Corrected invariant | Exact `re.md` section | Required tests | Remaining nonclaim |
|---|---|---|---|---|---|---|
| Portable authority identity correlates personas | P1 | A host-wide `authority_instance_id`, common broker/device identity, and attestation fields could appear in receipts and link personas | Every persona uses unrelated authority, approval, signer, and provider-enrollment identities; host/service/device common values are local-only and prohibited from every export | §4.1–§4.5; §6.2–§6.3 | Same-key enrollment rejection; A-as-B; host-ID leakage; device-certificate leakage; replaced/revoked enrollment; complete exported-field correlation (§12.1–§12.2) | No anonymity against content, timing, external key reuse, network observers, or recipient collusion |
| Authority state may commit before signatures exist | P1 | Prepared state/consent steps could advance authority before the complete signature set and verification | Pending/prepared/consent/signature states are non-authoritative; only one CAS into `Committed` after all signatures/material/receipt verify may change authority, followed by reread before release | §7.1–§7.2; §8.1–§8.3 | Pre-sign commit injection; missing-role commit; transaction/fsync crash; final-head race; reread mismatch (§12.3) | A committed but temporarily undeliverable result is an availability risk, not an unauthorized commit |
| Existing personas lack a Tier-2-to-Tier-3 bridge | P1 | “Adoption” did not produce the mandatory existing portable continuity transition or define where Tier 3 begins | Selected option B uses one ordinary exact dual-signed routine transition; old key supplies only previous role, new qualified key supplies next; atomic activation; history stays Tier 2 | §9.4; §10 | Accepted migration; old-key unavailable; wrong old key/role/namespace; interrupted migration; lost response; second transition retry (§12.1–§12.3) | Migration does not retroactively protect old history or prove which same-user process invoked the old key |
| Receipt construction depends on proof bytes not yet created | P2 | Receipt claimed a final proof digest before the unprivileged proof builder produced it | AR binds canonical semantic signed material; proof is built later; `proof_file_sha256` is prohibited and there is no finalize phase | §6.1–§6.5 | Material reconstruction; altered semantic field; receipt/proof mismatch; forbidden proof-file claim; proof reserialization (§12.2) | Receipt does not attest filename, wrapper, formatting, archive placement, or final serialized bytes |
| Routine transitions do not always require both protocol signatures | P2 | Policy language made old/new signatures conditional and allowed authority substitution | Exactly one previous and one next signature are unconditional, byte-identical, fixed-namespace, role-bound, and verified as a complete unchanged portable chain; AR is never a role | §5.3; §6.2; §7.2; §9.3; §10 | Removed/altered signature; duplicate/mislabelled role; optional-signature policy; AR-as-role; complete chain (§12.1–§12.3) | Two valid signatures do not by themselves establish freshness, absence of forks, safety, or legal identity |
| Idempotency ID may be unavailable after interrupted first submission | P2 | Authority-generated request ID might be lost after journaling, preventing exact lookup | Caller persists a 256-bit nonce before send; tuple plus full request digest is reserved before interaction and drives query/retry/conflict/retention | §5.2; §8; §9.6 | Disconnect at every journal point; same/same; same/different; abandoned GC; cancellation races; response lost (§12.1, §12.3) | Caller-side loss of both its nonce and complete request remains an availability failure, not permission to guess or resubmit |
| AuthorityReceipt hostile and negative vectors are incomplete | P2 | Receipt/enrollment/parser/privacy/tampering cases and failure-stage/state/evidence outcomes were underspecified | Positive and negative fixtures cover construction, crypto, semantic binding, enrollment, persona privacy, replay, parsing, policy, state, and exact retry with explicit stage/change/evidence | §12.1–§12.6 | Every applicable row in §12, including hostile vectors and installed/physical-path gates | Passing designed vectors is not independent review or proof of implementation correctness |

The seven earlier findings are addressed by design invariants and acceptance
requirements. This is not an implementation or independent-review conclusion.
The current revision also makes the following assurance decisions explicit:

| Design issue | Defined resolution | Evidence/qualification boundary |
|---|---|---|
| Trustworthy consent coupled to a phone checkpoint | Protected local physical consent and state define baseline Tier 3; no external checkpoint acknowledgement is required to release an already committed result | §§2.2, 7–9, 11.3 and 12.4; physical path still must be built and qualified |
| Local consent confused with whole-machine rollback prevention | Consent/profile/requirements are signature-bound; `required` fails before Pending in the baseline | §§2.4–2.5, 5–6 and 12.6; no concrete preventive protocol is declared complete |
| History comparison described as fresh signer enforcement | Separate proof/pin comparison, provenance and freshness reporting; head-only evidence omits ordinary signing-result state | §§2.3–2.4, 6.5 and 12.5; witnessed publication/freshness remains pending |
| Future gate bypassed by restoring old local policy/software | Preventive qualification must place enforcement outside the restored domain and cover promised operation state before signer use | §§2.4 and 12.6; a local flag or after-sign acknowledgement cannot qualify |
| Reference hardware becomes a product constraint | General Linux security contract with per-target qualification; Asahi, Hyprland and systemd are reference integration details | §§3.5, 11.5 and 12.4; no claim that every existing distro/driver/session qualifies |
| Receipt accidentally attests proof serialization | Require canonical sidecar bytes while preserving receipt validity across semantically identical valid ordinary proof serializations | §§6 and 12.2; final archive/file layout remains outside the claim |

## 16. Design consistency audit

| Check | Required result |
|---|---|
| General Linux scope | Common process/device/consent/state contract; no Asahi, Apple, Hyprland, systemd or exact build dependency in portable assurance |
| Physical consent available now in principle | Existing Linux interfaces are sufficient building blocks for the selected construction; implementation and per-target qualification remain required |
| Browser or phone as prerequisite | Neither is required for the selected local profile |
| Root-owned process confused with trusted display | Physical ownership, nested untrusted desktop and protected attention/decision path remain mandatory |
| Stable identifier across personas | Distinct random per-persona keys/IDs; common device/host/account/installation values excluded from exports |
| Common attestation restores correlation | Ordinary portable evidence excludes it; local-only qualification is not remote attestation |
| Authoritative commit before complete signatures | Prohibited; only the verified atomic `Committed` transaction changes authority |
| Pending/enrollment preparation described as authority | Explicitly false; pending keys and request/consent/provider records cannot activate a persona |
| Optional routine signature or AR as continuity role | Prohibited; exactly one previous and one next SSHSIG remain mandatory |
| Receipt covers unbuilt final proof bytes | Prohibited; it binds canonical semantic material and requirements |
| Authority builds general proofs | Unprivileged builder does so after verified commit and reread |
| Retry needs an authority-generated ID | Caller nonce plus complete request digest identifies the exact request |
| Same nonce accepts different request | Conflict before new consent/signing; exact committed retrieval remains historical |
| Migration relabels Tier 2 history or bypasses old key | Prohibited; mandatory dual-signed transition or existing authorized recovery; no retroactive assurance |
| Local baseline implicitly promises coherent whole-machine rollback resistance | Explicitly excluded; desktop-reachable restore paths still fail isolation |
| Local hash/counter becomes independent evidence | Prohibited; source independence and freshness require separate evidence |
| Existing continuity checks called a shipped fresh witness | Prohibited; implemented comparison and pending witness infrastructure are distinguished |
| Continuity head covers every artifact-signing result | False; non-history-changing result/nonce/receipt state needs separate coverage if prevention is promised |
| After-sign checkpoint called prevention | Prohibited; any future preventive profile must gate the signer before use and survive restored policy/software |
| Stronger required policy silently dropped | Prohibited; baseline returns `UnsupportedAssurancePolicy` before Pending/consent/signing |
| Phone checkpoint required for committed-result delivery | Removed; verified exact historical result can be returned without fresh consent or a witness |
| Mutable provider path or desktop bus becomes authority | Prohibited; fixed per-persona slots and authenticated closed private sockets |
| Offline receipt implies live authorization | Prohibited; local authority assertion, independent history and stronger requirements are separate results |
| Designed vectors described as completed tests | Prohibited; §12 is an acceptance plan, with existing continuity implementation distinguished |
| Wallet or unrelated issue scope expands | Official-wallet presentation stays separate; no transaction signing, plugin analysis or gpgv implementation |

This document defines the owner-selected direction and its reviewable
requirements. Service implementation, installed-system qualification and
independent security review remain separate work.
