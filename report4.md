# Report 4 — Local trusted consent using existing Linux facilities

Date: 2026-09-05

Scope: [issue #68](https://github.com/SurreptitiousFabric/a-quo/issues/68),
following the owner's request to assess this Linux machine without a browser
or dependence on future upstream fixes. This is a design analysis, not an
installed implementation or an acceptance of the proposed Tier 3 profile.

## Finding

**Yes: a local trusted-consent path is implementable using facilities already
present in this Linux stack.** The strongest construction is a system-owned
outer compositor that permanently controls physical display and input, with
the ordinary Hyprland desktop running inside it as an untrusted client.

This is an engineering conclusion from the existing interfaces and target
observations. It is not a claim that the complete construction has been run
or security-qualified on this MacBook. It requires local software and changes
to session startup and device permissions; installing an ordinary consent
window does not provide the boundary.

The current configuration cannot support the claim. In addition to the input
exposure identified in `report2.md`, this audit found unrestricted access from
the desktop account to a root-running Docker daemon.

No phone, browser, extra keypad, kernel patch, or future secure-attention API
is intrinsic to the proposed construction. Validation is work on our local
implementation, not a reason to wait for Linux to acquire a missing primitive.

## Evidence from this machine

The read-only host audit observed:

| Area | Observation | Consequence |
| --- | --- | --- |
| Kernel | `linux-asahi 7.1.6.asahi1-1`; running `7.1.6-1-1-ARCH`, aarch64 | Existing Asahi stack is the target. |
| Desktop | Hyprland `0.56.1-3`, Aquamarine `0.14.0-2`, systemd `261.2-1-arch` | Version-specific nesting support can be inspected. |
| Session | UID 1001, Wayland session 2, seat0, active VT2 | Today the ordinary desktop owns the physical session. |
| Display | `card2` uses `apple-drm`; eDP connected, HDMI disconnected | One system owner can manage the currently used display; newly connected outputs must also be controlled. |
| Rendering | Separate `renderD128` exists | GPU rendering can be separated from display-control access. |
| Keyboard | Physical Apple SPI Keyboard at `event1`, with a platform/SPI sysfs path | A built-in physical source exists for a protected attention chord. The event number itself is not an identity. |
| Input permissions | `swa` belongs to `input`; evdev and `/dev/uinput` are group-writable | The present desktop can inject input. |
| Synthetic input | An active ydotool device is under `/devices/virtual/input/` | Existing virtual devices and inherited access must be cleared before establishing a protected profile. |
| Administrative access | `swa` belongs to `docker`; `/run/docker.sock` is `root:docker`, mode 0660; `dockerd` runs as UID 0; authorization plugins reported `null` | The assumed boundary between desktop malware and root does not currently exist for this account. |
| Kernel facilities | VT, DRM, Apple DRM, evdev, cgroups, cgroup BPF, seccomp and AppArmor are enabled in the installed kernel configuration | Basic isolation and device-control building blocks are available. Configuration presence is not proof of an enforced policy. |

The first sandboxed queries hid device nodes and supplementary groups. The
observations above use the subsequent host queries outside that sandbox.
No input events, private keys, passwords or credential payloads were read.

Docker explicitly documents that its group grants root-level privileges.
Removing this rootful socket capability, for example by using an appropriately
configured rootless development setup, is a prerequisite. A different UID for
A Quo cannot withstand an attacker who can become host root through Docker.
Other administrative paths still need a deployment audit; wheel membership
alone was not treated as evidence of passwordless root.
[Docker's privilege documentation](https://docs.docker.com/engine/install/linux-postinstall/)

## Construction with existing interfaces

```text
Built-in display and physical keyboard/trackpad
                       |
                       v
Protected outer compositor — dedicated system UID
  owns KMS and physical input throughout the login session
  recognizes the physical attention chord
  selects either desktop content or protected consent content
           |                              |
           v                              v
Nested Hyprland — UID 1001        Native A Quo consent renderer
ordinary desktop applications     separately protected, fixed code/assets
no physical device control        bounded authoritative request only
                                          |
                               private, versioned SOCK_SEQPACKET
                                          |
                                 Separate A Quo authority
                                 protected policy/state and signer access
```

The diagram describes trust relationships, not a requirement to put all
components into one process. A narrow system supervisor arranges device FDs,
service identities and startup. The long-lived compositor and renderer need
not run as root. The existing per-user daemon remains a proposal/relay and
proof-building component.

Three existing building blocks support this design:

1. **Display ownership.** Linux already separates current DRM-master display
   control from render-node GPU access. Render nodes do not grant modesetting
   or the legacy global buffer-name interface. The guard retains the display
   authority and never exports protected scanout buffers to the desktop.
   This assumes correct kernel/driver isolation, as #68 already does.
   [Linux DRM interface documentation](https://docs.kernel.org/gpu/drm-uapi.html#render-nodes)
2. **Nested Hyprland.** The matching Hyprland source registers a Wayland
   fallback backend. Aquamarine's matching implementation connects to a
   parent compositor and receives keyboard/pointer events through Wayland.
   Its buffer feedback path prefers an available render node. This is
   existing functionality, not a proposal for upstream.
   [Hyprland 0.56.1](https://github.com/hyprwm/Hyprland/blob/v0.56.1/src/Compositor.cpp#L285),
   [Aquamarine 0.14.0](https://github.com/hyprwm/aquamarine/blob/v0.14.0/src/backend/Wayland.cpp#L90)
3. **An embeddable compositor.** Libweston provides compositor functionality
   for custom environments; Weston documents DRM/evdev and nested Wayland
   backends. It is a possible implementation base. Stock Weston, kiosk-shell
   or a second Hyprland instance is not already an A Quo consent system: the
   privileged-client policy and consent state machine must be implemented.
   [Libweston](https://wayland.pages.freedesktop.org/weston/toc/libweston.html),
   [Weston's backends](https://wayland.pages.freedesktop.org/weston/toc/running-weston.html)

An important target-specific integration constraint: Aquamarine 0.14.0 requires
`linux-dmabuf` feedback plus its expected seat, compositor and shell protocol
versions. A bare software-only parent offering just shared-memory surfaces is
not enough. On Asahi, feedback must select a usable rendering device with
`renderD128`, rather than forcing the nested desktop to open the protected
`apple-drm` primary node. Buffer formats/modifiers and rendering/display-device
interoperation require an integration test. Do not solve an incompatibility
by granting physical display access back to the desktop.
[Matching Aquamarine requirements and device selection](https://github.com/hyprwm/aquamarine/blob/v0.14.0/src/backend/Wayland.cpp#L136)

## Required local policy

The following are requirements of this construction, not claims about current
configuration:

- Start the system guard before untrusted desktop processes, from a trusted
  boot and root-owned service configuration. Establish clean device ownership
  at that point; changing permissions during the current session does not
  revoke already-open FDs or undo an earlier compromise.
- Keep the physical seat, KMS primary nodes, framebuffer, physical input and
  relevant device-management interfaces outside the desktop's authority.
  The nested login must not regain them through logind `TakeDevice`, uaccess
  ACLs, another VT login, seatd, hidraw/usbfs, uinput or an administrative API.
  Use system-owned permissions and device policy across all desktop processes.
- Restrict the physical VT/session's control as well as its device nodes.
  Desktop-controlled session switching must not expose desktop content while
  consent remains armed. A system-approved suspend, switch or restart cancels
  the current consent instance before relinquishing protected presentation.
- The guard reads only enrolled physical input sources, identified through
  trusted device topology, and forwards ordinary input to nested Hyprland.
  It consumes the attention chord itself. Neither the raw keyboard FD nor an
  input-injection interface into the guard is available to desktop clients.
- A trusted client connection is assigned by the system supervisor through
  a private channel. An application name, PID supplied by the caller, window
  title or `app_id` never grants access to protected presentation.
- The public desktop connection has no privileged shell, screen-capture,
  physical-output-management, input-emulation or remote-control authority
  over the protected domain. Pointer locks and shortcut inhibitors cannot
  suppress the physical attention chord.
- Root-owned code, libraries, assets and configuration define the guard and
  renderer. User themes, scripts, plugins and session environment are outside
  them. A compositor compromise remains a failure of the trusted computing
  base; nesting does not eliminate hostile protocol parsing.

Input permission removal is substantive. Linux's evdev write path injects
events into the underlying input device, while uinput creates virtual devices.
A grab or a familiar keyboard name does not authenticate event provenance.
The permanent ownership arrangement prevents those writable physical paths
from reaching the desktop in the first place.
[Linux 7.1 evdev write implementation](https://github.com/torvalds/linux/blob/v7.1/drivers/input/evdev.c#L465),
[Linux uinput documentation](https://docs.kernel.org/input/uinput.html)

## One local approval ceremony

1. The separate authority validates a closed request, derives the canonical
   signing facts and sends the bounded consent request to the protected side.
   A desktop request cannot approve or silently enter an armed state.
2. The user presses the reserved physical chord on the built-in keyboard.
   The outer guard consumes it, stops forwarding input and hides all desktop
   surfaces, cursors, overlays and other outputs that could imitate consent.
3. The protected renderer presents the exact operation, persona, purpose,
   signer roles/keys, policy/head and request binding. Long values remain
   inspectable. The presentation must use guard-owned buffers, with no
   dependency on completion of attacker-controlled rendering or fences.
4. The guard waits for the protected frame to be committed for display, then
   requires a neutral keyboard state. Only a fresh approval gesture after
   that barrier can create a decision. Physical input received during an
   incomplete transition cannot approve later.
5. The protected side sends one result bound to the request digest, persona,
   operation, nonce, expiry, protocol version and current protected instance.
   The authority authenticates and consumes it once, revalidates state, and
   only then permits the qualified signer operation.
6. A protected-state loss or uncertainty before the result is finalized
   cancels. Teardown follows the defined terminal acknowledgement; a crash
   never restores an armed request into the ordinary desktop.

This must be one serialized consent state machine covering input, presentation
and result finalization. A periodic "still on the right VT" check is not
sufficient to close a race. Trusted frame ownership must persist while the
approval event is accepted and finalized. The kernel and physical display
remain assumptions; there is no claim to attest that a human read pixels.

An imitation inside Hyprland cannot intercept the reserved physical chord or
provide the authority's result. The system must show the actual request after
the chord even if the nested desktop is frozen, malicious or disconnected.
If protected presentation cannot be established, there is no approval. A
logo, familiar colour or randomly displayed number is not the trust anchor.

## Why the earlier VT uncertainty is avoidable

`report2.md` considered taking physical display authority away from an already
running, potentially hostile compositor. Its retained-FD and handoff tests
are relevant to that particular construction. They do not establish a missing
Linux feature for every local construction.

With the outer guard, the desktop never owns the physical KMS master or raw
keyboard. Entering consent changes the trusted owner's presentation and input
routing; it does not negotiate a handoff with Hyprland. Both the internal
panel and HDMI can belong to the same protected owner. A second physical seat
is unnecessary.

| Local approach | Assessment |
| --- | --- |
| Existing direct-Wayland helper under desktop Hyprland | Cannot provide #68's boundary against compromise of that desktop UID/compositor. |
| Root-owned popup, ordinary screen lock or stock SAK signal alone | Does not establish the complete display/input/result boundary. |
| Reserved VT with protected input broker or permanently reserved keypad | Still a viable smaller experiment using current facilities; hostile display handoff remains its main integration burden. |
| Permanent system compositor with nested desktop | Strongest construction for the present question; avoids hostile ownership transfer and can use the built-in keyboard. Requires a new session architecture. |

Traditional Linux SAK itself is documented as an incomplete secure-attention
implementation. The proposed physical chord is handled by the protected input
owner and drives its own closed state machine; it does not rely on that name
or on a system-bus signal granting consent.
[Linux SAK documentation](https://docs.kernel.org/security/sak.html)

## Relationship to the rest of #68

The local display path solves only the consent boundary. The separate authority
must still own persona/policy/head state and enforce exact-byte request binding,
qualified service-only signer access, post-sign verification, cancellation and
idempotent result handling. A desktop-accessible SSH agent or FIDO endpoint does
not become exclusive merely because a protected prompt exists. Portable proof
semantics and per-persona separation remain intact. Consent/signing authority
continues to use private versioned Unix sockets, not D-Bus.

There is one material change from the external-device design in `re.md`:
**a wholly local design does not supply an independent checkpoint against a
coherent rollback of the whole machine.** If protected state, keys, journals
and every local checkpoint are restored together, ordinary local software
cannot distinguish the restored history from an earlier valid state. A
signature or a second local database cannot repair that.

Protected local state can resist substitution or rollback by the restricted
desktop UID, and durable transactions can address defined crash cases. An
independent witness or qualified non-rollback hardware would be needed for
the stronger whole-machine-rollback property. The local profile must explicitly
scope this claim rather than silently preserving `re.md`'s external-checkpoint
language. Root/kernel/firmware compromise remains outside #68's local claim.

Accessibility also belongs inside the trusted path. The native renderer can
provide scaling, keyboard navigation and complete text semantics. A protected
screen reader needs a private trusted accessibility connection and protected
speech output; the compromised desktop's screen reader or audio server cannot
authenticate the spoken request. On Asahi, a protected audio design must also
preserve the platform's required speaker-protection processing. This is local
integration work, with an enlarged trusted computing base, not evidence that
browser approval or future upstream APIs are mandatory.
[Asahi's audio-stack design](https://asahilinux.org/docs/sw/audio-userspace/)

## What remains to build and demonstrate

The material cost is a new system session boundary and a compositor/protocol
attack surface, plus effects on capture, remote control, global shortcuts,
display configuration, accessibility and performance. This is larger than an
A Quo application change, but it is a finite local engineering project.

The first demonstration should use inert requests and no signer. Its decisive
observations are:

- Nested Hyprland works with render-only access and the required buffer
  protocols; no process in the desktop domain can acquire physical devices.
- A frozen or malicious nested client cannot prevent the guard from hiding
  its content, intercept the physical chord or inject an approval event.
- Hostile client buffers, cursors, protocol messages, output changes and GPU
  stalls cannot leave consent armed over untrusted or incomplete presentation.
- Held keys, hotplug, suspend, guard crash and cancellation races produce no
  late or duplicated result. Cross-request, cross-persona and stale-instance
  result substitutions fail.
- Protected presentation and accessibility remain usable on the internal
  panel at the intended scale.

These tests distinguish a correct implementation from a flawed one. They
cannot be replaced by citing a standard, and their absence today must not be
reported as proof that Linux needs an upstream fix.

Recommendation for #68: pursue the permanent system compositor/local native
consent profile if changing the session architecture and administrative access
is acceptable. The source-backed feasibility answer is yes; the complete
profile's implementation and target qualification are still outstanding.

## Follow-up — is independent whole-machine rollback protection required?

**It is not an inherent requirement of trustworthy consent or a mandatory
property of issue #68 as written. It is an additional requirement in the
current `re.md` draft.** The issue asks for protection against ordinary
desktop-user malware, separates consent from state integrity, and explicitly
requires protection or stated nonclaims for the different assets. It does not
grant a blanket claim against root-equivalent authority or promise freshness.
Its rollback and crash requirements still need to be addressed; they cannot
simply be removed along with the external approval device.
[Issue #68](https://github.com/SurreptitiousFabric/a-quo/issues/68)

The recommended division is:

| Property | Baseline local higher-assurance tier | Separate history/rollback assurance |
| --- | --- | --- |
| Exact protected display, physical consent and request binding | Required | A witness cannot replace consent. |
| Exclusion of desktop access to signer, authority policy and state | Required | A witness cannot repair direct signer access. |
| Stale requests, partial writes, crash recovery, known state loss and replay | Required fail-closed handling and durable local transactions | Retained independent state can assist explicit reconciliation. |
| Old or competing signed history supplied to a verifier | Verify against that verifier's independently obtained expectations where available | Claims are relative to the retained checkpoint and its provenance/freshness. |
| Coherent restoration of every protected local state copy | Explicit baseline nonclaim; known restore/loss must not automatically resume authority from user files | Requires a checkpoint surviving outside the restored state, or qualified non-rollback hardware. |

The baseline must enforce protected **locally accepted** policy and history.
It must not describe that policy as globally current without additional
evidence. If an ordinary desktop process can restore the protected store or
control its restore API, the baseline implementation fails its own boundary;
calling that a whole-machine-rollback nonclaim would be invalid.

### What continuity already implements

The core verifies a chain against a separately supplied root and exact head
sequence/digest. A root alone accepts a valid historical prefix; an exact
later head expectation rejects that prefix and a different branch. The
matching regression explicitly exercises both behaviors. The verifier still
reports that checkpoint provenance, later transitions and withheld competing
transitions are not established.
[Core checkpoint verifier](crates/a-quo-core/src/continuity.rs#L975),
[existing regression](crates/a-quo-core/tests/continuity_round_trip.rs#L272),
[continuity contract](docs/CONTINUITY.md#status-and-meaning)

Archive comparison also checks explicit latest recovery-policy expectations.
It remains evidence-only, and matching does not itself create signing
authority. The separate materialization paths have additional gates.
[Independent checkpoint comparison](docs/CONTINUITY.md#independent-checkpoint-comparison)

These mechanisms can support independent history checking without a phone.
The checkpoint must actually survive independently of the restored machine;
another file in the same restored image supplies no independence. Nor does an
out-of-band pin automatically establish that its source has the latest state.

**An operational external-witness/freshness system is not already complete.**
The continuity documentation explicitly lists independently witnessed
root/policy publication and freshness as pending. Existing Sigstore evidence
for software artifacts is not a witness for A Quo persona or authority state.
[Pending continuity work](docs/CONTINUITY.md#deliberately-pending)

### Detection and prevention are different guarantees

Suppose an independent verifier retains persona head 12 and receives a valid
history ending at head 10. Existing checkpoint verification can reject it.
That does not, by itself, stop a machine restored to head 10 from invoking its
old signer before the verifier sees the output. A fresh, authentic local
consent interaction can still review stale policy after such a restoration.

If a deployment requires **preventing signer use after whole-machine rollback**,
it needs an independently enforced freshness/state check before signer access,
with defined concurrency and failure behavior. Periodic publication or
checking only after a signature is produced supplies a weaker guarantee.
A transparency inclusion proof alone also does not select one authoritative
branch or prove there is no later state.

Moreover, the existing `PersonaContinuityCheckpoint` contains only a transition
sequence and digest. Ordinary artifact signing in `re.md` commits an exact
result and receipt without advancing the continuity history. A history pin
alone therefore cannot establish that no signing-result records were lost,
that a receipt counter was not rolled back, or that authority/provider policy
outside that history is unchanged. Stronger rollback prevention requires an
explicit commitment covering the state relevant to the promised property;
it cannot be claimed by renaming the existing head pin.
[Checkpoint type](crates/a-quo-core/src/continuity.rs#L132),
[proposed operation ordering](re.md#72-operation-specific-ordering)

### Consequence for the design

Keep the protected local consent path from this report. Revise the proposed
tier so it requires same-user state isolation and crash/replay correctness,
while reporting independent history freshness and whole-machine rollback
protection separately. A persona policy may require the stronger property;
when it does, missing witness evidence must block its operation rather than
silently relaxing that policy.

This would be an explicit design change: `re.md` currently makes external
checkpoint confirmation a release condition and requires a later device
checkpoint to reject restored service state. Its operation sequences, recovery
rules and acceptance vectors must agree with the revised claim. Merely removing
the phone from its diagram would leave contradictory requirements.

The conclusion is therefore **no phone is required merely for trustworthy
consent**. Independent rollback protection can be designed and evaluated
separately. Existing continuity verification provides part of that separate
mechanism; it does not justify claiming that external witnessing or preventive
whole-machine rollback resistance has already been delivered.

This follow-up inspected the implementation and existing regression source;
it did not run the regression or change proof formats. The relevant continuity,
store and threat-model files match the locally retained `origin/main` revision.

## Review record

Only this new report was written. `re.md`, `report2.md`, `report3.md`, tracked
source, system configuration and GitHub objects were not changed. No desktop
restart, VT switch, device grab, input injection, container creation, signer
operation or hardware experiment was performed. Rust checks were not run
because this task changed no Rust code.

The host observations came from package/kernel queries, `id`, `loginctl`,
device metadata/ACLs, sysfs and input-device metadata, process UID inspection,
and the narrowly formatted read-only `docker info` fields recorded above.
The same kernel version remains running. Source inspection used matching
Hyprland/Aquamarine upstream tags; installed distro binaries were not proven
byte-identical to those source tags.

Earlier report hashes at the start of this review:

```text
re.md       0386ec2df46e731408fd120109b204ffcbe60bef3d876368d873ccfadf7f7539
report2.md  0c6cf54152e329e7a054a48f044af75bc547236a38db79c9821b0d621941856e
report3.md  fedfe962cdb8a9d7f9cef7265091029e516464b235155187fb2a14b1ecbd4e2e
```
