# Accessibility and trusted consent

Status: **requirements baseline for issue #6; current direct-Wayland consent
prototype does not yet meet this contract**

A Quo asks users to approve security-sensitive actions. An approval is valid
only if the user can perceive the authoritative facts, reach a safe choice,
and deliberately confirm the exact action. Accessibility is therefore part of
the security boundary, not a later visual polish task.

This document inventories every current trusted prompt and freezes the v1
keyboard, screen-reader, scaling, focus-loss, timeout, and hostile-text
requirements. It does not claim that screen-reader support, complete reflow, or
the future install/update prompt already exists.

## Authority must not move to D-Bus

The consent authority remains the focused private Wayland process and its
inherited result pipe:

```text
untrusted same-UID requester
          |
          v
private signing daemon derives a closed prompt subject
          |
          v
trusted direct-Wayland consent process
          |       \
          |        +--> read-only accessibility semantics (future)
          v
direct keyboard/pointer decision
          |
          v
one bounded result on inherited private pipe
```

The current prototype deliberately does not use D-Bus or a desktop portal as
its approval channel. That rule remains.

A future accessibility bridge may publish read-only names, descriptions,
roles, ordering, focus state, and text values so a screen reader can describe
the trusted window. It must not expose an action, writable value, synthetic
key, click, confirmation, or approval method on D-Bus/AT-SPI. Messages from an
accessibility bus client never approve, decline, choose a recovery role, alter
a displayed value, extend a deadline, or produce the result sent to the daemon.

Read-only is an authority property, not a confidentiality claim. Any same-UID
client permitted to inspect the accessibility bus may be able to read the
persona label, domain, digest, ceremony ID, checkpoint, or other value currently
shown. A Quo cannot authenticate a process as “the user's real screen reader.”
The v1 bridge therefore requires a user-controlled local accessibility mode
selected before a request; neither the requester nor prompt data can enable it.
When enabled, the product states this same-session disclosure tradeoff plainly.
Objects exist only for the active prompt, use no stable cross-prompt identifier,
contain exactly the validated fields belonging to the active trusted page
(including its offscreen scroll content), retain no history, and disappear on
cancellation or close. A future page and hidden daemon/request state are not
exported. Credential presentations and any new sensitive prompt need a separate
disclosure review before joining this bridge.

If the platform accessibility protocol cannot support a useful read-only view
without exposing callable authority, that limitation must be resolved by a
reviewed design before implementation. It is not acceptable to add a generic
bus method and rely on caller identity or UI convention.

## Current trusted prompt inventory

The approval protocol currently has five closed subject types. Caller prose
cannot add a sixth type or replace the typed authoritative fields.

| Subject | Authoritative information shown | Deliberate action |
| --- | --- | --- |
| `Artifact` | persona label and purpose; caller-supplied artifact label and caller-selected kind both marked as display context; daemon-derived exact size and SHA-256 digest; signing-key fingerprint; caller PID/UID | **Sign bytes** |
| `Domain` | persona and purpose; canonical DNS name; issued/expiry times and duration; exact TXT publication value; signing-key fingerprint; caller PID/UID | **Sign claim** |
| `PersonaRoot` | persona and purpose; anchor; issued time; exact root digest; signing-key fingerprint; caller PID/UID | **Create root** |
| `PersonaTransition` | persona and purpose; anchor; sequence and issue time; pinned root; prior head; old/new key fingerprints; exact transition digest; caller PID/UID | **Rotate key** |
| `RecoveryParticipation` | full persona label; anchor; ceremony ID and expiry; daemon-derived role and participant fingerprint; root/policy version, threshold, digest and head pins; reason, sequence, previous/next/participant fingerprints; exact request digest; two-signature/hardware notice; caller PID/UID | **Sign response** |

The recovery prompt is deliberately split across two pages. The user must view
both pages before approval can become available. Its role is derived from the
validated ceremony and selected signing reference; the caller does not choose
an authoritative role label.

Common local protocol data also includes the request UUID and local persona
UUID/correlation information used by the daemon. A value needed for local
binding is not automatically appropriate for disclosure. UI implementations
show only the fields defined for the prompt and must never expose private-key
locators, agent sockets, portable recovery secrets, credential contents, or
unrelated persona records.

See [Approval protocol](APPROVAL-PROTOCOL.md),
[Consent IPC](CONSENT-IPC.md), and [Daemon](DAEMON.md) for the typed protocol and
trust boundary.

## Prompt types that do not exist yet

The current inventory does **not** include:

- Omarchy install/update risk consent;
- recovery-policy enrollment or policy update;
- terminal persona revocation;
- direct archive activation and recovery archive activation;
- zero-authority terminal archive hydration;
- adoption/commit of an assembled recovery transition; and
- external credential-wallet presentation consent.

Command-line text, `--yes`, and the prototype's separate
`--accept-behavioral-analysis-not-run` acknowledgement are not substitutes for
a trusted prompt.

The future Omarchy install/update approval is a new closed subject. It must show
the exact package and publisher evidence, structural facts, attributed risk
reports, limitations, unknowns, update delta, local policy result, destination,
and action described in [Plugin risk evidence](PLUGIN-RISK.md). It must not
reuse `Artifact` with a caller-generated risk summary.

Every future prompt named above must likewise receive a separately reviewed
typed subject and threat analysis before it becomes a trusted product action.

## What the current prototype does

The current consent process:

- renders its own software framebuffer into an ordinary direct-Wayland
  `xdg_toplevel` process;
- reads direct keyboard and pointer input;
- begins with **Decline** focused;
- supports `Tab`, `Shift+Tab`, `Enter`, `Space`, and `Escape`;
- requires a separate confirmation control before approval;
- clears confirmation and active presses when keyboard focus is lost;
- returns focus to **Decline** after focus loss;
- returns recovery participation to its first page after focus loss;
- returns cancellation on timeout, close, renderer failure, or protocol
  failure; a broken result pipe prevents delivery but is not currently observed
  while the UI is still displayed;
- has a 90-second consent deadline, with the parent enforcing a bounded
  95-second process lifetime;
- rejects unsafe prompt strings at the protocol boundary and renders accepted
  strings as plain text.

The prototype uses fixed nominal windows: 780×760 logical pixels for ordinary
prompts and 780×900 for detailed transition/recovery prompts. Detailed prompts
fail closed when the active output/scale cannot fit their required dimensions.
Ordinary prompts do not yet have equivalent complete fit/reflow enforcement.

The ordinary prompt renderer middle-truncates some persona and artifact labels.
Recovery deliberately wraps the full persona label. Any truncation of an
identity label or other security-relevant value is a known gap under this v1
contract.

The prototype does not publish screen-reader semantics. The absence of an
AT-SPI accessibility path is already identified as a security/accessibility
gap in the [threat model](THREAT-MODEL.md).

The current Wayland toplevel is not a secure-attention surface and cannot
prevent another same-UID client from drawing a convincing imitation. The user
must not be told that the window provides phishing-proof consent.

## v1 interaction principles

Every trusted prompt must satisfy these principles:

1. **Decline is always safe and reachable.** Closing, timing out, losing the
   renderer, or receiving ambiguous input cancels.
2. **Approval takes more than one accidental input.** A user reviews the
   subject, selects confirmation, and then activates the action.
3. **The exact value wins over a friendly summary.** Full digests,
   fingerprints, identities, roles, destinations, and unknowns remain
   available and are never replaced by caller prose.
4. **No colour-only meaning.** State is communicated with text, shape, focus,
   and semantics as well as colour.
5. **Focus loss destroys partial consent.** Returning to the window begins from
   a conservative state.
6. **Accessibility output is not approval input.** In an explicitly enabled
   accessibility mode, a screen reader—and potentially another eligible
   same-UID client—may observe the trusted surface; a bus client cannot operate
   it.
7. **Failure is explicit.** Missing glyphs, clipping, inaccessible controls,
   protocol errors, and inability to fit required facts cancel rather than
   hiding information.

## Keyboard requirements

All functionality must be possible without a pointer.

### Focus order

The initial focus is **Decline**. The order then follows the visible reading
order and ends with confirmation and the affirmative action. `Tab` moves
forward; `Shift+Tab` moves backward; wrapping behaviour is consistent and
documented. Hidden or disabled controls are not focus stops.

For two-page recovery consent:

1. initial focus is **Decline** on page one;
2. the page-one continuation is reachable only after the page content is
   present and perceivable;
3. page two begins at **Decline**, not confirmation or approval;
4. approval remains disabled until page two has been visited in the current
   uninterrupted focus session;
5. returning to page one clears confirmation;
6. focus loss returns to page one and clears all partial state.

Future multi-page prompts follow the same fail-closed rule.

### Key behaviour

- `Enter` and `Space` activate only the currently focused control.
- `Escape` cancels immediately and cannot be rebound by prompt data. It is not
  recorded as an explicit activation of **Decline**.
- Key repeat cannot toggle confirmation repeatedly or cross from confirmation
  into approval.
- Press on one control and release on another does not activate either.
- Pointer activation does not alter the keyboard safety sequence.
- Unrecognised keys and composed text do not approve.
- Shortcuts, mnemonics, input methods, and accessibility clients cannot bypass
  the explicit confirmation state.
- The affirmative action has a textual verb specific to the subject; it is not
  a generic “OK.”

Visible focus meets contrast requirements and is not indicated solely by a
subtle colour change. Focus remains identifiable at every tested scale.

## Focus-loss, disconnect, and cancellation requirements

On keyboard focus loss, output removal, compositor disconnect, renderer crash,
parent/daemon disconnect, or protocol read/write failure, the process:

1. clears confirmation, pressed-state, visited-page, and affirmative-focus
   state;
2. invalidates any pending approval result;
3. either cancels immediately or returns to a defined conservative state with
   **Decline** focused;
4. never resumes an approval after the deadline;
5. emits at most one bounded final result on the inherited pipe.

Focus loss during key-down is tested separately from loss before key-down and
after release. Repeated focus changes must not extend the deadline. A late UI
approval racing daemon cancellation/expiry is rejected by the daemon at the
post-consent boundary.

Closing the window is cancellation. There is no “remember approval,” automatic
approval, background approval, or approval by notification action in v1.

## Screen-reader requirements

Before screen-reader support may be marked complete, the read-only semantics
tree must expose:

- a unique trusted-window title that states the action;
- prompt subject type and page number/count;
- ordered section headings;
- complete labels and complete values for every authoritative field;
- whether text is caller-supplied, locally derived, provider-attributed, a
  limitation, or an unknown;
- control role, accessible name, focus, enabled/disabled state, confirmation
  state, and the consequence of activation;
- warning and error priority without repeatedly interrupting ordinary reading;
- remaining-time warnings at useful fixed thresholds.

The screen reader must be able to read security-relevant values character by
character. A friendly label does not replace a digest or fingerprint. General
clipboard export is outside v1: the compositor clipboard is another
same-session disclosure channel, and a future copy feature requires a separate
explicit user action, lifetime/ownership policy, and privacy review.

The timer must not announce every second. At minimum, time remaining is
available on request and changes are announced at 30 seconds and 10 seconds;
expiry announces cancellation. Those thresholds may be adjusted only by a
reviewed local product policy, not caller input.

### Read-only bus security tests

Tests run a hostile same-UID D-Bus/AT-SPI client that attempts to:

- invoke every advertised method;
- write values, focus, state, or selection;
- synthesize click/key/action events;
- race semantics updates with direct input;
- forge a sibling window or object path;
- keep a stale object alive after cancellation;
- flood queries or disconnect/reconnect the bus.

No attempt may alter UI state, extend time, select a role, or generate an
approval. Sensitive fields not present on screen must not appear in bus
properties, errors, logs, object paths, or accessible descriptions.

Privacy tests also prove that the requester cannot enable accessibility mode,
disabled mode exports no prompt tree, enabled mode exposes no more than the
validated fields of the active trusted page (including designed offscreen
scroll content), object paths and IDs do not correlate
prompts, cancellation removes every A Quo-owned object, reconnection cannot
recover content from the A Quo bridge, and A Quo retains no clipboard or
accessibility cache. An external screen reader or hostile same-UID bus client
can copy or retain any visible exported value; A Quo cannot prove or force its
deletion. That residual disclosure is documented, not hidden as a passing
privacy test.

Screen-reader failure does not silently switch to an inaccessible approval
path. Until an accessible trusted flow is available, the product reports the
limitation and provides a safe non-digital or independently reviewed route
where the operation requires one.

## Scaling, reflow, and visual requirements

Security-relevant text must fit without truncation at supported scales. A
prompt may scroll only if:

- the scroll container is reachable and operable by keyboard and screen
  reader;
- the UI clearly states that more authoritative content follows;
- approval is unavailable until every required section has been made
  perceivable in the current focus session;
- focus loss resets that visited state;
- the decline action remains visible or immediately reachable.

Digests and fingerprints may wrap at deterministic character boundaries but
may not use ellipsis. Persona labels, plugin IDs, versions, domain names,
destinations, roles, finding titles, limitations, and unknowns may wrap or open
a trusted detail view; they may not be middle-truncated in the only view.

The minimum v1 visual test matrix is:

| Output | Scale |
| --- | ---: |
| 1280×720 | 100% |
| 1920×1080 | 100% |
| 1920×1080 | 150% |
| 1920×1080 | 200% |
| HiDPI output | 200% |
| Representative output | 125% fractional |
| Representative output | 150% fractional |
| Representative output | 200% fractional |

Tests use compositor scale factors `1`, `1.25`, `1.5`, and `2` where supported.
Every cell in the published v1 matrix must successfully present and operate
every current prompt, using the guarded scrolling rules above where necessary.
Failing closed is acceptable for an output/scale combination outside the
published supported matrix, but does not turn a failed matrix cell into a
successful accessibility result. In every unsupported case, confirmation is
unavailable and the UI explains how to retry on a suitable output.

Text and essential icons meet WCAG 2.2 AA contrast: at least 4.5:1 for ordinary
text, 3:1 for large text, and 3:1 for meaningful UI components and focus
indicators. Warnings, findings, unknowns, disabled state, and provider status
use words/icons as well as colour. Layout remains usable with increased text
size and does not depend on animation; reduced-motion preference is respected.

Screenshots at every scale are regression artefacts, but screenshot comparison
alone is insufficient. Tests also assert semantic order, full rendered values,
focus reachability, and pixel bounds.

## Unsafe and difficult text

All prompt strings are untrusted until validated by their typed protocol.
Accepted strings render as inert plain text. They are never interpreted as
QML, Pango/HTML markup, terminal escapes, Markdown links, shell fragments, file
URLs, or bidirectional formatting instructions.

The current protocol rejects leading/trailing whitespace, control characters,
line/paragraph separators, Unicode default-ignorable and bidirectional control
characters, zero-width characters, and other forbidden display input. That
validation remains necessary but is not sufficient: the renderer and
accessibility bridge must also handle legal difficult text consistently.

The test corpus includes:

- maximum-length UTF-8 at every field bound;
- combining marks and canonical-equivalent forms;
- right-to-left scripts without bidi control characters;
- mixed left-to-right/right-to-left labels;
- confusable Latin, Cyrillic, and Greek characters;
- emoji and multi-code-point grapheme clusters;
- very long unbroken identifiers, paths, DNS labels, digests, and fingerprints;
- embedded quote/bracket/colon characters that resemble UI syntax;
- missing-glyph and font-fallback cases;
- rejected newlines, tabs, escape bytes, NUL, bidi overrides, zero-width, and
  default-ignorable characters;
- provider evidence excerpts that resemble buttons, links, warnings, or
  authoritative field labels.

The UI visually distinguishes an untrusted label or provider excerpt from an
authoritative digest/value. Confusable warnings may be additive, but A Quo must
not claim it can identify every deceptive Unicode string. If a glyph cannot be
rendered and the exact value cannot be exposed safely, approval is unavailable.

Accessibility text is derived from the same validated typed value as visible
text. It must not use a second lossy sanitizer, caller-provided alternate label,
or truncated display cache.

## Time and cognitive accessibility

The current 90-second deadline is a security bound, but it may be insufficient
for users reading a complex recovery or plugin-risk prompt with assistive
technology. User testing must measure this before release.

If more time is required, the eventual duration is a reviewed, bounded local
policy selected before the request. It is never chosen or extended by the
caller, prompt contents, D-Bus, pointer hover, focus churn, or accessibility
queries. The deadline remains visible/available, and expiry always cancels.

Plain-language summaries precede dense values, but summaries never replace
them. Related facts are grouped consistently. Recovery pages explain why two
signatures may occur and which role is being exercised. Risk prompts explain
facts, inferences, limitations, and unknowns before using those terms.

## Required automated and human tests

Every current and future trusted subject must pass:

1. keyboard-only traversal and activation tests;
2. initial-decline and focus-order assertions;
3. focus loss at every state and during every press/release boundary;
4. timeout, daemon disconnect, compositor disconnect, and duplicate-result
   races;
5. semantic-tree snapshots with full values and correct attribution;
6. hostile accessibility-client attempts with no authority transfer;
7. the scaling/reflow matrix above, including largest legal field values;
8. colour/contrast, high-contrast theme, colour-blind, reduced-motion, and
   missing-glyph checks;
9. the unsafe/difficult-text corpus above;
10. screen-reader exercises with at least one Orca-compatible path where the
    reviewed implementation supports it;
11. human testing with keyboard-only, low-vision, and screen-reader users;
12. confirmation that logs, crash output, accessibility objects, and IPC errors
    do not disclose hidden locator or persona-correlation data.

The recovery prompt additionally tests both pages, role derivation, participant
fingerprint, ceremony expiry, hardware-backed two-signature messaging, and
reset to page one. The future plugin prompt additionally tests long finding
sets, provider failure, material unknowns, update deltas, and refusal to approve
when required content cannot be perceived.

## Release gate

Issue #6 is not complete until:

- every current prompt satisfies this contract without security-relevant
  truncation;
- a useful screen-reader path has independent security review;
- the accessibility interface has no approval authority;
- accessibility mode and its same-UID disclosure boundary are user-controlled,
  ephemeral, minimized, tested, and documented;
- keyboard, scaling, hostile-text, timeout, focus-loss, and bus-adversary tests
  run in CI or a documented compositor test environment;
- human accessibility testing has occurred and findings are tracked;
- documentation states the remaining secure-attention/phishing limitation;
- future prompt types cannot enter release without the same checks.

Until then, the direct-Wayland consent work is an advanced prototype with known
accessibility gaps, not release-ready trusted consent.
