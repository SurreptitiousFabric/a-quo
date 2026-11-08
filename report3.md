# Report 3 — Browser-based second-device approval with WebAuthn/passkeys

Date: 2026-09-04  
Scope: focused feasibility investigation for A Quo issue #68  
Repository basis: \`origin/main\` at \`a10a371f2bed300a78beabc72f58bf27abc31b8d\`, the complete untracked \`re.md\`, and the independent same-machine investigation in \`report2.md\`

## Verdict

**BROWSER-SECOND-DEVICE-CONDITIONALLY-FEASIBLE**

A phone browser can replace the proposed numbered keypad as A Quo's independent consent display and input surface. A normal “open this URL and approve with your passkey” flow cannot, by itself, make the Tier 3 claim.

The feasible profile is narrower:

- the user independently opens a fixed, dedicated HTTPS approval origin on the phone;
- a small, trusted web client verifies an authority-signed, closed A Quo consent request and displays every authoritative fact;
- a per-persona phone-bound approval channel, enrolled through a channel not controlled solely by the desktop, proves that the ceremony ran in the enrolled phone browser;
- WebAuthn with user verification supplies a request-specific proof of local user presence/verification;
- the authority, not the relay or web server, verifies the raw WebAuthn assertion and the phone-channel result;
- no response is accepted unless it binds the exact persona, operation, canonical statement, nonce, state, expiry and one protected-session instance;
- all loss, navigation, timeout, replacement and recovery paths fail closed.

Ordinary Apple iCloud Keychain passkeys, Google Password Manager passkeys and other synced passkeys cannot be the sole approval identity. They may be usable as the phone-local user-verification factor only when a separately enrolled, non-synced phone-channel key or equivalent device-bound session is also mandatory. A synced credential may otherwise be usable from the compromised Linux machine, and a WebAuthn assertion does not cryptographically identify the browser or physical device from which it was requested.

This is a viable architecture direction, not yet an implementation-ready profile. The remaining decisive feasibility question is whether the supported phone/browser matrix can provide a persistent, per-persona, non-synced phone-channel key/session with the required lifecycle and accessibility behavior. Plain WebAuthn does not provide that property. Current general-purpose Device Bound Session Credentials are still a draft/limited browser mechanism and explicitly do not protect use by malware resident on the same client.

## Executive assessment

The central question is:

> Can browser-based second-device approval using WebAuthn/passkeys supply the exact Tier 3 properties missing from the desktop consent path?

**Yes, if the phone browser is treated as the external trusted approval device and WebAuthn is only one component of that device protocol. No, if “passkey” is treated as a magic substitute for trusted display, phone identity, enrollment, checkpointing or exact request binding.**

The product intuition is sound. After a one-time trustworthy enrollment, the routine ceremony can be:

1. the desktop says that approval is waiting and shows a short request number;
2. the user independently opens the known A Quo approval URL on the phone;
3. the user enters or selects the number;
4. the phone verifies and displays the exact A Quo operation;
5. the user deliberately chooses Approve;
6. Face ID, Touch ID, a device PIN, or another WebAuthn user-verification method authorizes the assertion;
7. the authority accepts the result only if every cryptographic and live-state check succeeds.

The short number is only a locator and human cross-check. It is never a bearer credential, challenge, approval token or source of entropy.

This avoids reliance on Hyprland, Wayland overlays, Linux input authenticity, VT switching, DRM ownership and the audited host's current \`uinput\` exposure. Malware on the Linux desktop can still create fake A Quo windows, suppress or flood requests, and lie about success. It cannot produce a valid phone-channel result for an undisplayed request. Denial of service and social pressure remain nonclaims.

The cost is a different trusted computing base: the phone OS, browser, authenticator/passkey provider, approval web client, HTTPS origin and its deployment path become security-critical. That is a reasonable product trade only if issue #68 states it explicitly.

## Relation to the current design

The selected design in \`re.md\` already requires:

- an independently authenticated display/input device at lines 35–44;
- exact request-specific consent for the Tier 3 claim at lines 108–118;
- an approval device that verifies the authority challenge, displays exact fields, signs a request-bound decision and maintains a checkpoint at lines 168–175;
- an authenticated authority-to-device request and device-to-authority token at lines 183–195;
- fresh, unrelated approval keys per persona at lines 244–282;
- a non-circular pairing route at lines 1129–1137;
- exact display rather than touch/PIN alone at lines 1139–1145; and
- consent before signer invocation or authoritative commit at lines 711–735.

A qualified browser profile can instantiate those requirements. It does not remove them. In particular, the browser page is the approval-device application; WebAuthn user verification is the local authorization gesture; and a phone-bound per-persona channel key is the approval-device identity. Calling a synced passkey itself the “approval device” would weaken the current design.

## What WebAuthn guarantees—and what it does not

The current primary standard is [Web Authentication Level 3, W3C Recommendation, 25 August 2026](https://www.w3.org/TR/webauthn-3/).

| Property | Classification | Consequence for A Quo |
|---|---|---|
| A credential is scoped to an RP ID and the client supplies an origin | **SPECIFICATION GUARANTEE**, with correct RP verification | Use exactly one dedicated RP ID and one exact HTTPS origin. Do not accept related origins, subdomains or arbitrary callback origins. |
| The authenticator signs \`authenticatorData || SHA-256(clientDataJSON)\` | **SPECIFICATION GUARANTEE** | The authority can verify a signature over the exact client-data challenge and origin. |
| \`clientDataJSON\` includes the ceremony type, challenge, origin, \`crossOrigin\`, and, where applicable, \`topOrigin\` | **SPECIFICATION GUARANTEE** | Require \`webauthn.get\`, the exact expected challenge, the one allowed origin, \`crossOrigin=false\`, and no unexpected top origin. |
| Authenticator data binds the RP ID hash, user-presence flag, user-verification flag, backup flags, counter and signed extensions | **SPECIFICATION GUARANTEE** | Verify all fields directly. Require UP and UV. Reject unknown critical policy inputs and inconsistent backup flags. |
| The BE flag identifies a multi-device credential and cannot change after registration | **SPECIFICATION GUARANTEE** | BE=1 proves that the credential is multi-device. BE=0 does not prove which browser invoked the assertion. |
| A passkey assertion proves the user reviewed the A Quo statement | **NOT ESTABLISHED** | WebAuthn authenticates a challenge. It does not standardize an A Quo transaction display. |
| The authenticator independently parses the A Quo statement | **NOT ESTABLISHED** | The authenticator normally sees only a client-data hash and has no A Quo parser. |
| UP or UV means informed approval of the displayed statement | **NOT ESTABLISHED** | UP/UV proves an authenticator interaction/local verification, not why it occurred or what the user understood. |
| The assertion identifies the physical phone, browser instance or transport used | **NOT ESTABLISHED** | A separate phone-bound channel or a specifically qualified device-bound implementation is required. |
| \`authenticatorAttachment\` or transport hints are a signed device-location proof | **NOT ESTABLISHED** | They cannot be accepted as evidence that the ceremony ran in the enrolled phone browser. Transport values are discovery hints. |
| A signature counter is monotonic and always nonzero | **OPTIONAL** | WebAuthn permits a constant zero counter. It cannot be A Quo's checkpoint or rollback authority. |
| Attestation proves that the user enrolled the intended phone | **NOT ESTABLISHED** | Attestation can describe authenticator provenance; it does not make a compromised enrollment channel non-circular. |
| \`largeBlob\` or PRF supplies a portable monotonic checkpoint | **OPTIONAL / NOT ESTABLISHED** | Neither is a general, monotonic, non-rollback device-state primitive. |
| The RP web application is protected from same-origin code compromise | **NOT ESTABLISHED** | W3C explicitly warns that malicious code at the RP origin can invalidate WebAuthn guarantees. The origin and client deployment are in the TCB. |

[Secure Payment Confirmation](https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260604/#sctn-cryptographic-evidence) makes the missing distinction explicit: plain WebAuthn has no specified UX for transaction information placed in a challenge. SPC adds a browser-controlled display and, in the 2026 draft, a browser-bound key—but only for its closed payment schema. It is not a general A Quo statement-confirmation API, is still a Candidate Recommendation Draft, and must not be repurposed by pretending A Quo operations are payments.

The earlier WebAuthn \`txAuthSimple\`/\`txAuthGeneric\` ideas are not an available escape hatch. The working group removed unimplemented transaction-authorization extensions; see [W3C WebAuthn issue #1386](https://github.com/w3c/webauthn/issues/1386).

## Decisive findings

### P1 — A synced passkey is not an exclusive second-device approval key

**Failure scenario.** A persona's ordinary passkey syncs through iCloud Keychain, Google Password Manager or another credential provider. It becomes available to a browser on the compromised Linux desktop, or the phone authenticator is reachable through a hybrid/cross-device ceremony. Malware obtains the A Quo challenge, invokes WebAuthn for the genuine RP origin, induces a generic biometric/PIN interaction, and returns a valid assertion without the user ever seeing the authoritative A Quo fields in the trusted phone page.

Apple states that its passkeys synchronize through iCloud Keychain across Apple devices ([Apple Passkeys](https://developer.apple.com/passkeys/)). Google documents Google Password Manager passkey synchronization across Android and Chrome environments, including Linux ([Google passkey environments](https://developers.google.com/identity/passkeys/supported-environments)). The signed WebAuthn BE bit exposes multi-device eligibility, but the assertion does not state “this came from the enrolled phone page.”

FIDO guidance distinguishes synced passkeys from device-bound credentials for higher-assurance deployments: [FIDO authentication for moderate assurance](https://fidoalliance.org/white-paper-fido-authentication-for-moderate-assurance-use-cases/) and [FIDO high-assurance enterprise authentication](https://fidoalliance.org/white-paper-high-assurance-enterprise-fido-authentication/).

**Minimum correction.** A Tier 3 browser profile must either:

1. combine WebAuthn with a separately enrolled, per-persona phone-channel key/session that is unavailable to the desktop and that gates disclosure of the fresh challenge and signs the result; or
2. qualify a specific single-device WebAuthn implementation and prove that the credential cannot be invoked from another browser/device, including through hybrid transport.

The first is the recommended profile. BE=0 is valuable defence in depth, but is not by itself proof of the invoking browser. A BE=1 passkey may be used only as a UV factor behind the mandatory phone-channel binding; it is not the approval identity.

**Blocks acceptance:** yes, if the design says “ordinary passkey” without the extra phone binding.

### P1 — WebAuthn does not attest to the A Quo facts displayed

**Failure scenario.** The web client displays benign statement A but asks WebAuthn to sign a challenge for statement B. The authenticator verifies the user locally and signs the challenge. The authority sees a valid WebAuthn assertion for B, but WebAuthn itself gives no evidence that A or B was displayed.

The standard says the authenticator signs the hash of client data but is otherwise not interested in its contents. The SPC specification exists partly because plain WebAuthn does not define a transaction-information display.

**Minimum correction.** The trusted phone client must:

- receive one authority-signed canonical consent envelope;
- strictly verify the authority signature, schema, canonical encoding, persona key pin, nonce, state and checkpoint;
- derive every displayed field from that envelope, never from separate relay-supplied display metadata;
- independently reconstruct or verify the canonical A Quo statement;
- compute the expected WebAuthn challenge from the exact envelope;
- call WebAuthn only after the complete display is visible and the user selects Approve; and
- bind the returned assertion to a phone-channel signature over that same envelope and decision.

The authority must recompute the challenge and verify the raw assertion. It must not trust a Boolean such as \`webauthn_ok\` from the web server.

**Blocks acceptance:** yes.

### P1 — A browser origin becomes an approval authority

**Failure scenario.** The approval origin, CDN, DNS/TLS deployment, third-party script or release pipeline is compromised. It serves client code that verifies nothing, clips important fields, or invokes WebAuthn for an attacker-selected pending request. Because it runs at the valid RP origin, origin binding does not protect against it.

WebAuthn's own [code-injection security consideration](https://www.w3.org/TR/webauthn-3/#sctn-code-injection-attacks) says malicious code executing at an allowed RP origin can invalidate WebAuthn security guarantees.

**Minimum correction.** Issue #68 must identify:

- the exact HTTPS origin and RP ID;
- who controls DNS, certificates, hosting and deployment;
- a no-third-party-script policy;
- a minimal static client and closed parser;
- reproducible/reviewed release and rollback policy;
- CSP and related hardening as defence in depth;
- how an old or compromised web client is rejected; and
- the explicit nonclaim that compromise of this origin/client, the phone OS, browser or authenticator provider defeats consent.

Subresource Integrity cannot pin the top-level HTML against the authority that serves it. A service worker does not make first installation or future updates independently trustworthy.

**Blocks acceptance:** yes, until the owner accepts and bounds this TCB.

### P1 — Routine number matching does not solve initial enrollment

**Failure scenario.** Desktop malware displays its own QR code or pairing secret and substitutes the attacker's WebAuthn credential or phone-channel key. Every later ceremony is cryptographically correct—but correct for the attacker-enrolled identity.

This is the same bootstrap issue already recognized at \`re.md\` lines 1131–1137. A short request number is particularly unsuitable for enrollment because it is neither secret nor an authenticated key fingerprint.

**Minimum correction.** Initial enrollment needs a direct or administrator-mediated path outside the compromised desktop UI. The authority and phone must bind, per persona:

- persona root/anchor;
- authority public key and epoch;
- WebAuthn credential ID, public key and algorithm;
- phone-channel public key/session identity;
- approval epoch and initial checkpoint;
- exact HTTPS origin and RP ID; and
- a registration nonce.

Registration must include immediate proof of possession from both keys. No passkey/account recovery flow may silently enroll a new phone channel.

**Blocks acceptance:** yes for new-persona Tier 3 and Tier-2-to-Tier-3 migration.

### P2 — WebAuthn supplies no A Quo rollback checkpoint

**Failure scenario.** Browser/site state is cleared or restored, the authority store is rolled back, and an obsolete approval enrollment or policy/head is presented as current. A zero or non-monotonic WebAuthn signature counter does not detect the rollback.

**Minimum correction.** The phone profile must maintain a per-persona checkpoint that binds at least authority epoch, approval epoch, continuity/policy head and last accepted approval sequence. Clearing or losing it must cause refusal and explicit recovery, never silent re-enrollment. If a remote witness stores it, that witness and its privacy behavior become part of the design. WebAuthn \`signCount\`, \`largeBlob\`, cookies and ordinary IndexedDB must not be described as independent monotonic protection without a qualified implementation and restoration analysis.

**Blocks acceptance:** yes for the complete \`re.md\` architecture; it does not block a consent-only prototype.

### P2 — The browser-to-authority route needs end-to-end request and result protection

**Failure scenario.** An untrusted desktop coordinator or public relay reads the WebAuthn challenge, presents it from a desktop browser that has the synced credential, swaps request display fields, or replays a valid result.

**Minimum correction.** The authority must create a fresh secret challenge component and encrypt the complete signed consent envelope to the enrolled phone-channel key before exposing it to the desktop relay. The phone must return a channel-authenticated result. The relay may know a short locator, ciphertext length and timing, but never supplies authoritative plaintext or a trusted verification result. Replays are harmless only when the authority has a one-use nonce/state record and returns the exact same terminal result.

**Blocks acceptance:** yes.

### P2 — Current browser device-binding mechanisms do not close the gap by themselves

[Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) is a promising browser mechanism, but the current document is an Editor's Draft. Chrome introduced it through an origin trial ([Chrome DBSC origin trial](https://developer.chrome.com/blog/dbsc-origin-trial)); a portable production baseline across iOS Safari and Android browsers is not established. More importantly, DBSC's own non-goals say that signing capability may remain available to software running as the user on that client and that it does not attest a particular device or device state.

The browser-bound key in Secure Payment Confirmation is payment-specific and draft. Neither primitive is a current general A Quo trusted-display API.

**Minimum correction.** Select and qualify an actually available phone-channel primitive rather than naming DBSC abstractly. A browser-held, non-exportable per-persona WebCrypto key plus an enrollment-only session may be sufficient against malware confined to the Linux desktop, but its persistence, backup, migration and browser support must be tested on every supported phone platform.

**Blocks acceptance:** yes until the primitive and support matrix are selected.

### P3 — Request numbers need anti-enumeration and anti-fatigue rules

A short number is good UX but poor security material. It must locate only an encrypted pending envelope, expire quickly, be rate-limited and be included inside the authenticated envelope for matching. Guessing a number must not disclose request facts, identify a persona, authorize a request or permit enrollment. Repeated prompts and fake desktop success screens remain denial/social-engineering risks; the phone page should show the authoritative terminal status.

**Blocks acceptance:** no, provided the number is explicitly non-authoritative.

## Minimum qualifying architecture

This is the single recommended browser profile. It does not use a numbered keypad or any other dedicated hardware.

### Components and trust boundary

\`\`\`text
  UNTRUSTED LINUX DESKTOP UID
  ┌─────────────────────────────────────────────────────────────┐
  │ caller / Hyprland UI / coordinator / network relay client   │
  │ may invent requests, lie, replay, delay, flood, or vanish   │
  └───────────────┬───────────────────────────────┬─────────────┘
                  │ closed local request           │ opaque ciphertext/result
                  v                                v
  PROTECTED LINUX AUTHORITY                  UNTRUSTED RELAY
  ┌──────────────────────────────┐           ┌──────────────────┐
  │ separate service UID         │<--------->│ mailbox/transport │
  │ protected persona state      │ ciphertext│ no approval power│
  │ canonical statement builder  │           └────────┬─────────┘
  │ WebAuthn + channel verifier   │                    │ HTTPS
  │ nonce/terminal journal        │                    v
  └───────────────┬──────────────┘       TRUSTED PHONE APPROVAL BOUNDARY
                  │ only after approval    ┌──────────────────────────────┐
                  v                        │ fixed HTTPS origin/client    │
           QUALIFIED SIGNER                │ strict A Quo request parser  │
           (unchanged by this report)      │ exact display + accessibility│
                                           │ per-persona channel key/state│
                                           │ WebAuthn client/authenticator │
                                           └──────────────────────────────┘
\`\`\`

The public relay is not the WebAuthn verifier and is not trusted to say what the phone displayed. The HTTPS origin is security-critical because it supplies the trusted approval code. Those roles may share infrastructure operationally, but the protocol must not confuse them.

### Mandatory phone state, per persona

Each persona has independent values:

- one pinned A Quo authority public key and epoch;
- one fresh phone-channel key pair or equivalent device-bound session;
- one fresh WebAuthn credential ID and public key;
- one random WebAuthn user handle containing no persona label, account name or PII;
- one approval epoch;
- one checkpoint over authority epoch, approval epoch, policy/continuity head and approval sequence; and
- no shared A Quo installation ID, browser ID, device certificate, cloud-account identifier or portable attestation.

“Phone-channel key” is shorthand for purpose-separated channel material: an
approval-authentication/signing key and a request-encryption/KEM key, or an
authenticated session construction that provides both properties. One
cryptographic key must not be reused across signing and encryption purposes.

The WebAuthn credential and channel key must not be reused across personas. The approval web service must not join personas through a shared account, cookie, local-storage namespace or server-side user record. A shared RP ID is protocol scope, not an identity, but the server must still prevent its operational metadata from becoming a persona-linking database.

### Closed consent request

The authority constructs one bounded canonical \`BrowserConsentRequestV1\`. It contains at least:

- schema and protocol version;
- approval profile and expected origin/RP ID;
- persona anchor/root and authority/approval epochs;
- operation type and exact purpose/namespace;
- canonical statement bytes, or the complete inputs from which the phone's closed parser reconstructs them;
- statement digest and size;
- all signer roles, provider class and public-key fingerprints that are authoritative for the operation;
- current policy, continuity/recovery head and proposed next head;
- caller nonce and complete authority request digest;
- an authority-generated 256-bit consent challenge secret;
- short request number as a non-secret locator/cross-check;
- prior and proposed device checkpoint;
- protected-session instance;
- expiry/timeout policy; and
- explicit decision value \`approve\` for the assertion challenge.

The authority signs this canonical object with the persona-specific authority key, then encrypts it to the persona-specific phone-channel key before the desktop or relay sees it. Separate unsigned “display fields” are forbidden.

The WebAuthn challenge is a domain-separated SHA-256 commitment to the entire signed canonical request, including the authority secret and the literal approval decision. It is not merely the statement digest and not the short number. The authority stores the exact expected challenge rather than accepting a client-recomputed value on trust.

### End-to-end ceremony

1. The untrusted desktop submits a bounded proposal with its persisted caller nonce. This grants nothing.
2. The authority validates protected state, constructs the exact canonical statement and request, writes only non-authoritative Pending state, generates the secret consent challenge, signs the request and encrypts it to the enrolled phone channel.
3. The desktop/relay receives only an opaque mailbox item and a short number. It may suppress, duplicate or delay either.
4. The user independently unlocks the phone and opens a pre-enrolled bookmark/home-screen entry for the exact approval origin. The user does not follow an arbitrary URL or QR code supplied by the compromised desktop for routine approval.
5. The user enters the short number or selects a pending item. The phone-bound session fetches the encrypted envelope.
6. The web client decrypts it locally, verifies the authority signature and pinned persona key, rejects stale epochs/checkpoints/noncanonical input, reconstructs or verifies the exact canonical statement, and renders every authoritative field. Failure, clipping, hidden fields, navigation or unsupported schema cancels.
7. The user checks the persona, purpose, operation, statement facts, signer/provider, policy/head and matching number, then deliberately selects Approve. Merely opening the page, entering the number, focusing a button or invoking an accessibility read action is not approval.
8. The top-level page invokes WebAuthn with exactly the enrolled credential, exact RP ID, \`userVerification=required\`, ordinary explicit mediation and the exact committed challenge. Iframes, related-origin fallback and conditional/silent mediation are prohibited.
9. The authenticator performs UP and UV and returns the raw assertion.
10. The phone client checks the returned client data locally, constructs a bounded \`BrowserApprovalResultV1\` over the request digest, approval decision, assertion digest, phone-session instance and next checkpoint, and authenticates it with the per-persona phone-channel key.
11. The relay returns the raw \`clientDataJSON\`, authenticator data, signature, credential ID, phone-channel result and required channel signature. The relay's interpretation is ignored.
12. The authority verifies bounds/canonicality, credential lookup, signature algorithm, exact type/challenge/origin/RP ID hash, UP, UV, \`crossOrigin=false\`, absence of an unexpected \`topOrigin\`, backup policy, extensions, phone-channel signature, persona/operation/statement/nonces, expiry, session instance, checkpoint and current protected state.
13. Only after all checks pass does the authority proceed to the signer phase defined by \`re.md\`. It revalidates again before signer access and before commit.
14. The authority commits the result under the existing sign-verify-commit invariant. It then acknowledges the exact checkpoint/result to the phone. A lost acknowledgement leaves a resolvable prepared checkpoint; it never authorizes a different request.
15. The phone displays authoritative committed, declined, cancelled or unresolved status obtained through the authenticated channel. A desktop “success” window has no evidentiary value.

### Why the phone-bound channel is mandatory

WebAuthn signs an RP challenge and origin, not “this exact browser instance displayed these facts.” A credential may be synced or usable through a cross-device authenticator path. The server cannot safely infer ceremony location from \`authenticatorAttachment\`, transport hints, a user-agent string, IP address or the BE flag.

The phone channel closes two gaps:

1. the fresh challenge secret is unavailable to the compromised desktop, so it cannot request a valid assertion there; and
2. the authority requires a result signature/session proof from the specifically enrolled phone browser in addition to the WebAuthn assertion.

If a future standardized browser-bound key provides these exact properties on all supported phones, it may instantiate the channel. It must be qualified against the same requirements; its name is not sufficient.

## Credential and provider matrix

| Credential or path | Sole Tier 3 approval identity | Role in recommended profile | Reason |
|---|---:|---|---|
| Apple iCloud Keychain passkey | **No** | Conditional UV factor only | Designed to synchronize across Apple devices; no proof that the assertion was invoked by the enrolled phone page. |
| Google Password Manager passkey | **No** | Conditional UV factor only | Designed to synchronize across Android/Chrome environments, including desktop environments. |
| Third-party password-manager passkey | **No unless independently proven device-bound** | Conditional UV factor only | Provider/account synchronization and recovery can copy signing capability. |
| A credential with signed BE=1 | **No** | UV factor behind the phone channel | The standard says it is a multi-device credential. |
| A credential with signed BE=0 | **Not by that fact alone** | Preferred defence in depth | BE=0 says single-device credential, not which client invoked it or whether hybrid transport can reach it. |
| Specifically qualified phone platform credential, BE=0, with proven no off-device/hybrid invocation | **Potentially** | May merge WebAuthn and channel roles | No current cross-platform consumer-phone profile has been established by this investigation; target testing and provider policy are required. |
| Synced passkey plus independent per-persona phone-channel key/session | **Yes, conditionally as a combination** | **Recommended** | The channel proves the enrolled phone context; WebAuthn supplies local UV and an origin/challenge-bound assertion. |
| Desktop-initiated WebAuthn hybrid/QR ceremony | **No** | Prohibited | The authoritative facts remain on the compromised desktop, and the phone authenticator need show only generic RP authentication. |
| Roaming FIDO security key | **Not the selected product profile** | Optional future authenticator | It may be device-bound, but is extra hardware and does not itself display the A Quo statement. |
| Secure Payment Confirmation browser-bound key | **No for A Quo** | None | It is a draft, payment-specific API and cannot express A Quo's closed non-payment operations. |
| Device Bound Session Credentials | **No current baseline** | Possible future channel component | Draft/limited availability; not a trusted-display primitive and has explicit local-use non-goals. |
| SMS, e-mail link, TOTP or number matching alone | **No** | Notification/locator only | Bearer or low-entropy values do not bind exact displayed statement semantics to the enrolled phone process. |

The authority must maintain an explicit provider/profile allow-list. Unsupported browser, authenticator, extension, backup state or algorithm fails Tier 3; it never falls back silently.

## Enrollment and trust bootstrap

### New Tier 3 persona

The new-persona bootstrap has two independent directions of trust:

- the phone must learn the correct persona-specific authority public key; and
- the authority must learn the correct phone-channel public key and WebAuthn credential public key.

If both arrive only through a screen controlled by the compromised Linux desktop, malware can substitute both sides and create a self-consistent false enrollment. WebAuthn attestation does not resolve that circularity: it may describe a credential's authenticator, but it does not say that the user intended this credential for this persona.

A feasible one-time ceremony therefore needs one of:

- installation/administrator-mediated enrollment where a protected authority action presents or transfers the persona-specific authority fingerprint and receives the phone keys;
- direct local authority-to-phone authenticated exchange whose endpoint and key are not chosen by the desktop; or
- an already enrolled approval device or previously authorized recovery route.

The exact administrator/direct mechanism is still an issue-#68 design decision. The routine “open URL and enter number” ceremony does not need to repeat it.

The enrollment record must be pending and non-authoritative until:

1. the phone verifies the authority key and exact enrollment statement;
2. the phone-channel key proves possession over that statement;
3. WebAuthn registration is fully verified;
4. an immediate WebAuthn authentication assertion proves possession and UV;
5. the authority verifies that the phone-channel and WebAuthn keys are fresh and not reused by another local persona;
6. the persona signer supplies every signature required by the existing root/enrollment design; and
7. the complete authority operation commits atomically.

Requesting \`attestation: none\` is the privacy-preserving default. If a provider must be qualified through attestation, the full chain/AAGUID and resulting device-class facts remain local enrollment evidence. They are not copied into portable proofs or receipts. Enterprise or unique-device attestation is not acceptable merely for convenience; its privacy and revocation consequences would require a separate explicit profile.

### Tier-2-to-Tier-3 migration

The same phone enrollment must be bound into the exact migration operation described at \`re.md\` lines 942–989. The phone displays:

- that history is currently Tier 2;
- old and new signer fingerprints and roles;
- exact continuity head and transition digest;
- new authority key/epoch;
- new phone-channel and WebAuthn enrollment digests;
- the assurance upgrade boundary; and
- nonce, request digest and matching number.

The old Tier 2 key remains only the previous-key signer; it cannot authenticate the phone enrollment against same-user malware because the attacker may already be able to use that key. The new provider, authority proof of possession, phone-channel proof and both continuity signatures must verify before commit. Tier 3 starts only at the committed transition.

### Planned phone replacement

Planned replacement requires:

- an exact, persona-bound replacement statement;
- approval by the old phone channel;
- proof of possession and UV from the new phone channel/WebAuthn credential;
- the current authority key and persona authorization required by \`re.md\`;
- an incremented approval epoch and checkpoint;
- revocation of the old phone enrollment at the same atomic boundary; and
- no portable shared device identifier.

The old and new phone credentials are never merged through a shared browser account in A Quo state.

### Lost phone, cleared site data or factory reset

These events are indistinguishable from loss of the approval key unless another enrolled device remains. They must not trigger passkey-only recovery, e-mail reset, cloud-account reset, desktop QR enrollment or Tier 2 fallback. The supported choices are:

- a previously enrolled second approval device under an explicit threshold policy;
- the authorized recovery ceremony selected for the persona; or
- a new persona/discontinuity when no authorized route remains.

Loss may make Tier 3 unavailable. That is preferable to silently granting the desktop a new approval authority.

## State, checkpoint and retry analysis

### State placement

| State | Required authoritative location |
|---|---|
| Canonical request, caller nonce, complete request digest and terminal result | Protected authority store |
| Persona authority key, signer/provider state, policy and continuity/recovery heads | Protected authority store and portable signed evidence as already defined |
| WebAuthn credential ID/public key/algorithm/BE policy | Protected authority store, per persona |
| Phone-channel public key, approval epoch and status | Protected authority store, per persona |
| Phone-channel private key/session | Enrolled phone browser/device boundary only |
| Authority public-key pin | Enrolled phone browser/device boundary, per persona |
| Last phone checkpoint and prepared/committed state | Phone boundary plus protected authority transaction |
| Relay locator/ciphertext | Untrusted, bounded, expiring relay storage |
| WebAuthn raw assertion and phone result | Protected pending/terminal operation record |
| Portable proof/AuthorityReceipt | Existing portable output; no WebAuthn or phone identity need be exported |

### Checkpoint rules

The phone must never infer “first use” simply because browser storage is empty. Empty, older, forked or unparsable state is a recovery condition.

For each request, the authority proposes a transition from exact checkpoint C to C+1. The phone prepares only that transition. After authority commit, an authenticated acknowledgement finalizes it. If the network fails:

- before WebAuthn: there is no approval;
- after WebAuthn but before the authority receives the result: exact retry may resend only the same result;
- after the authority receives/records approval but before signer work: authority pending state may resume only the exact request;
- after authority commit but before phone acknowledgement: query returns the same terminal result and finalizes the same checkpoint;
- after phone preparation but authority abort/cancel: the phone records the exact non-committed terminal outcome or resolves it through authenticated query; it must not reuse the approval for another request.

WebAuthn \`signCount\` is clone-detection input only. A zero counter is legal. It cannot choose between two coherent authority histories. Browser storage, cloud backup and remote witness behavior must therefore be explicit before the full anti-rollback claim is made.

### Replay and simultaneous requests

- One caller nonce/request digest maps to one authority operation.
- One authority consent secret maps to one exact challenge.
- One WebAuthn assertion and phone-channel result maps to one exact operation.
- Same nonce and same request returns/resumes the same operation.
- Same nonce with any changed request fails before a phone prompt or WebAuthn call.
- A result replay after commit returns the existing terminal result and performs no consent, signer access or mutation.
- A result replay against another persona, operation, checkpoint or service epoch fails.
- Two simultaneous phone submissions race on protected compare-and-swap state; at most the exact registered operation can advance.
- Terminal decline, cancel and expiration retain sufficient nonce/request tombstones to prevent a later replay from becoming a fresh request.

## Display and human-consent analysis

### What the phone must display

The page must display the values already required by \`re.md\`, specialized for each closed operation:

- persona name for human recognition and the persona/root fingerprint or another full inspectable stable persona-local value;
- exact purpose and signature namespace;
- operation type and consequence;
- canonical statement semantic fields;
- complete artifact digest and size where applicable;
- old/new signer roles and full fingerprints for transitions;
- provider class;
- policy and current/proposed continuity or recovery head;
- assurance-tier change, enrollment or revocation consequence;
- request nonce/digest in an inspectable details view;
- matching short request number;
- expiry and current phone/authority checkpoint state; and
- Approve, Decline and Cancel controls with unambiguous focus.

Long values may be summarized visually only if the complete value remains inspectable and copy is not accepted back as approval input. Truncation must use collision-resistant comparison conventions and expose both ends/full value. Hidden overflow, clipping, unsupported characters, bidi/control characters or parser ambiguity fails closed.

### Trusted-path procedure

The exact human procedure is:

1. notice a pending request on the desktop, without trusting its content;
2. independently unlock the already enrolled phone;
3. open the fixed A Quo approval bookmark/home-screen entry and check the real browser origin;
4. enter/select the request number on that phone;
5. read the authoritative details on the phone;
6. select Approve on the phone;
7. complete the phone's WebAuthn user verification; and
8. confirm the phone's authenticated final status.

The desktop must never tell the user to scan an arbitrary routine QR code or follow a supplied URL. A fake desktop screen can imitate the workflow, but it cannot access the phone channel, decrypt the request or create the final result. If it blocks the real request, the outcome is no signature.

The fixed origin is not sufficient human authentication on its own—a lookalike page can imitate it. Cryptographic safety comes from the genuine RP credential, pinned authority request and phone-channel key. The recognizable origin/bookmark reduces confusion; it is not treated as approval evidence.

### Prompt flooding and social engineering

The authority and phone profile need:

- one visible request per explicit user-selected mailbox item;
- bounded outstanding requests per persona/caller;
- rate limits and backoff;
- no push notification that can approve directly;
- clear requester-untrusted wording;
- no automatic WebAuthn invocation on page load;
- no conditional UI/autofill ceremony;
- timeouts that allow accessibility without leaving approvals indefinitely live; and
- an authenticated phone-side history of recent terminal outcomes.

Malware may still create plausible malicious statements and repeatedly ask. The positive Tier 3 claim is prevention of silent or forged approval, not proof that the user understood content or freedom from coercion.

## Result-channel analysis

The authority is the final WebAuthn relying-party verifier even if a remote HTTPS service participates. Verification includes:

1. exact credential ID lookup under the expected persona and approval epoch;
2. allowed COSE algorithm and exact stored public key;
3. raw \`clientDataJSON\` parsing with bounded length and no duplicate/ambiguous JSON handling;
4. exact \`type = webauthn.get\`;
5. byte-for-byte expected base64url challenge after standards-compliant decoding;
6. exact allowed origin;
7. \`crossOrigin=false\` and no unexpected \`topOrigin\`;
8. exact SHA-256 RP ID hash;
9. UP and UV set;
10. consistent BE/BS and selected provider policy;
11. allowed, fully parsed signed authenticator extensions only;
12. signature verification over the exact authenticator data and client-data hash;
13. phone-channel signature/session proof over the assertion digest and exact approval result;
14. exact persona, statement, operation, purpose, nonce, request digest, checkpoint, protected-session instance and expiry;
15. current authority state and unused/non-conflicting terminal record; and
16. immediate full revalidation before signer access.

Authentication at the public relay, an HTTP cookie, a TLS connection, JavaScript verification or a remote server's success response is never a substitute for these checks.

The browser page may show Decline without invoking WebAuthn if the phone-channel result authenticates the decline. Only an exact WebAuthn-plus-channel Approve result can unlock signer access. Cancellation, navigation, phone lock, visibility loss, process/page termination, WebAuthn abort, channel loss or timeout cannot be promoted to approval.

## Persona privacy analysis

### Deterministic cryptographic linking

The recommended profile does not add a deterministic cross-persona identifier to portable A Quo evidence if all of these rules hold:

- generate fresh authority, phone-channel and WebAuthn keys for every persona;
- use a random per-persona WebAuthn user handle;
- reject credential ID, public-key and channel-key reuse across local personas;
- request none attestation by default;
- keep AAGUID, attestation chains, BE/BS, credential IDs, RP account data, origin, user-agent and phone diagnostics out of portable proofs and AuthorityReceipts;
- expose only a digest of the exact approval result where receipt semantics require consent binding; and
- never derive keys or handles from a common A Quo installation/account root.

Two recipients cannot link personas from independent random public keys or receipt fields. They may link them from the content the user chooses to sign; that is not an A Quo-added authority identifier.

### Service and provider correlation

The approval web origin can create deterministic linking if it uses:

- one login account for all personas;
- one shared cookie/session;
- one installation/device identifier;
- analytics or third-party scripts;
- stable push-notification tokens;
- a common mailbox identifier; or
- server-side tables that join per-persona enrollments.

The profile must prohibit those behaviors or state that the service itself can correlate personas. A per-persona isolated browser storage/session is required. Whether mobile browsers can provide practical storage isolation without awkward separate profiles is a product and test concern.

Apple, Google or another passkey provider may internally know that several credentials belong to one cloud account. A Quo cannot honestly claim global anonymity from the provider. The relevant product claim is narrower: no shared provider/account identifier or attestation is exported in A Quo portable evidence.

IP address, timing, TLS fingerprint, notification timing, ciphertext length and common phone/browser characteristics can create probabilistic metadata correlation. They must be reported separately from deterministic cryptographic linkage. Padding, minimal retention and no third-party telemetry reduce but do not eliminate it.

## Hosting, network and trusted computing base

### Network shape

A fixed public HTTPS origin is the most practical routine UX. A direct LAN address or \`.local\` name is not automatically a WebAuthn secure origin and introduces certificate/discovery problems. The \`http://localhost\` exception would refer to the phone itself, not the Linux laptop.

The authority service does not need general network access. An unprivileged coordinator may relay opaque encrypted messages:

- authority signs and encrypts request to phone;
- coordinator uploads ciphertext to a bounded mailbox;
- phone downloads/decrypts and uploads an authenticated encrypted result;
- coordinator fetches and returns it to the authority.

The relay can observe availability metadata and deny service, but cannot change the displayed request or forge approval. The design continues to use the closed private Unix-socket protocol locally; D-Bus is not approval authority.

### Tier 3 trusted computing base

The browser profile must trust:

- Linux kernel, service manager, root-owned package path and separate-UID authority boundary already assumed by \`re.md\`;
- authority request canonicalizer, signer-independent consent state machine, encryption, WebAuthn verifier and phone-channel verifier;
- persona-specific authority and phone-channel keys/checkpoints;
- HTTPS origin ownership, DNS, certificate issuance/renewal and deployment credentials;
- approval HTML/JavaScript/WASM, its strict canonical parser, renderer and accessibility behavior;
- phone browser and its same-origin/storage isolation;
- phone OS and secure-lock/biometric/PIN subsystem;
- passkey/authenticator provider and any cloud synchronization it performs;
- phone-channel storage/session primitive;
- remote relay availability and metadata handling, though not its statement/result integrity; and
- the signer boundary only after consent, unchanged from issue #68.

The approval client must not contain:

- the general portable-proof parser or builder;
- SQLite/persona-database handling;
- signer execution;
- archive, package, plugin, media or wallet parsing;
- arbitrary URLs or third-party content;
- generic network discovery;
- analytics/advertising;
- arbitrary configuration; or
- cryptocurrency/blockchain transaction logic.

Its job is one closed request, one exact display and one decision.

### Explicit nonclaims

The profile does not resist:

- root/host-administrator, kernel or protected authority compromise;
- compromise of the phone OS, browser, WebAuthn authenticator/provider, approval origin/client or phone-channel storage;
- compromise of signer firmware/service;
- a malicious biometric/PIN enrollee accepted by the phone OS;
- physical coercion or a user deliberately approving a deceptive statement;
- denial of service, prompt flooding or notification suppression;
- observation of non-secret approval facts by the relay unless end-to-end encryption is implemented as required;
- global anonymity or non-correlation by Apple, Google, the network or the approval service;
- trusted time/global freshness without an external witness;
- truth, safety, provenance or legal identity of signed content;
- unsupported browsers/authenticators/platforms; or
- cryptocurrency/blockchain transaction signing.

## Accessibility assessment

This profile is materially more promising than a small keypad/display because a phone browser can provide:

- screen readers;
- zoom, reflow, large text and high contrast;
- visible keyboard/switch focus;
- external keyboard and switch-control support;
- localization and bidirectional-text handling;
- scrollable full fingerprints/digests;
- longer, configurable but bounded timeouts; and
- explicit cancel/retry/status views.

WebAuthn Level 3 recommends supporting multiple user-verification methods and ceremony timeouts long enough for users with disabilities ([WebAuthn accessibility considerations](https://www.w3.org/TR/webauthn-3/#sctn-accessibility-considerations)).

The authority rule is:

- accessibility may read/navigate the verified phone display and invoke the ordinary Approve control;
- the final authority-bearing event is still the WebAuthn assertion plus phone-channel result;
- no accessibility API, desktop screen reader, remote-control session or push action can synthesize that result without the phone authenticator's required UV and enrolled channel;
- screen-reader output never becomes a separately trusted statement source; and
- inability to expose every authoritative field accessibly fails the profile for that platform.

This requires real VoiceOver, TalkBack, switch-control, large-text, reduced-motion and external-keyboard testing. A malicious phone accessibility service falls under phone OS/application compromise; the design must say so. A legitimate accessibility workflow that uses device PIN rather than biometrics must remain supported where the authenticator reports UV.

## Attack matrix

| Hostile scenario | Outcome in qualifying profile | Enforcing mechanism / residual risk |
|---|---|---|
| Fake A Quo window in Hyprland | Prevented from approving | Desktop UI is untrusted; phone-channel key and challenge secret are absent. Fake window may confuse or deny service. |
| Hyprland overlay/layer-shell surface | Prevented from approving | It cannot cover the phone display or generate phone result. |
| Desktop alters canonical statement after request | Prevented | Authority-signed encrypted envelope, exact challenge commitment and final state comparison. |
| Desktop supplies benign display fields beside malicious bytes | Prevented | Phone derives all display from the signed canonical envelope; separate fields forbidden. |
| Desktop opens the genuine RP origin | Prevented from approving | It lacks the enrolled phone channel and encrypted challenge secret. A synced passkey alone is insufficient. |
| Synced passkey appears on Linux desktop | Prevented from being sole authority | Mandatory phone-channel proof; BE policy recorded. |
| Desktop starts WebAuthn hybrid flow using phone | Prevented from approving | Exact challenge is available only inside the enrolled phone channel, and result needs channel signature. Generic phone UV cannot substitute. |
| Lookalike phone origin | Prevented cryptographically | Wrong RP/origin and no enrolled channel key. It may phish/confuse but cannot create accepted result. |
| Compromised genuine approval origin | **Not prevented** | Explicit excluded authority; origin/client is in the TCB. |
| Malicious phone OS/browser | **Not prevented** | Explicit excluded authority. |
| Relay changes or truncates request | Prevented/detected | Signature, authenticated encryption, canonical bounds; cancellation. |
| Relay withholds request/result | Denial of service | Availability nonclaim. |
| Relay replays old request | Prevented | Nonce, request digest, expiry, checkpoint and terminal journal. |
| Relay replays valid assertion for another request | Prevented | Challenge commits to exact signed envelope and authority one-use state. |
| Attacker guesses short number | No authority or plaintext | Number is only a rate-limited locator for encrypted data. |
| Attacker floods numbered requests | Bounded denial/social pressure | Authority quotas, phone selection, no automatic prompts/WebAuthn. |
| Number displayed differently on desktop | Detected by human or harmless | Phone's signed number is authoritative; number grants nothing. |
| Same persona request opened twice on phone | Exactly one result | Protected nonce/terminal record and checkpoint CAS. |
| Two personas share one passkey | Rejected | Authority detects local credential/public-key reuse; profile requires fresh per-persona keys. |
| Shared passkey-provider account | Provider may correlate | No portable identifier; synced credential is not sole authority. Global anonymity is a nonclaim. |
| Shared browser cookie links personas | **Profile violation** | Per-persona isolated sessions; must be tested and enforced. |
| WebAuthn UP without UV | Rejected | Authority requires signed UP and UV flags. |
| Touch/Face ID/PIN without statement review | Possible user error, not silent forgery | Trusted client displays first and invokes only after Approve; WebAuthn alone never claimed as review proof. |
| WebAuthn assertion from an iframe/related origin | Rejected | Exact origin, top-level flow, \`crossOrigin=false\`, no unexpected \`topOrigin\`. |
| Old browser protocol | Rejected | Minimum protocol/profile version inside the signed request/result and checkpoint; unsupported schema fails closed. |
| Vulnerable or stale web-client code that claims a current version | **Not independently attestable with plain WebAuthn** | Origin deployment/cache/service-worker controls and mobile-client TCB must prevent it. A JavaScript version string is not proof of running code. |
| Old authority state shown to phone | Rejected where checkpoint retained | Persona-specific checkpoint. Cleared/rolled-back phone state requires recovery. |
| Browser site data cleared | No approval | Channel key/checkpoint absent; explicit recovery, no passkey-only reset. |
| Phone factory reset or replacement | No approval | Old enrollment remains authoritative until planned replacement/recovery. |
| Phone navigation/background/lock before result | Cancel/no approval | Client lifecycle plus authority expiry/session state; target tests required. |
| Network loss after WebAuthn assertion | Exact retry only | Pending exact result and nonce; no new WebAuthn or alternate operation. |
| Authority cancels while phone later approves | Rejected | Live terminal state and expiry rechecked before signer access. |
| Signer completes after consent/request cancellation | Existing \`re.md\` state machine rejects commit/release | Consent result cannot reopen terminal operation. |
| Desktop shows fake success after rejection | No authority | Phone/portable verifier shows authenticated state; desktop presentation is non-authoritative. |
| Accessibility client reads facts | Allowed | Read access carries no approval authority. |
| Accessibility invokes Approve button | Still requires UV and channel result | Legitimate activation path; phone OS/accessibility compromise remains excluded. |
| Remote-desktop software on Linux | Prevented from approving | It controls only the untrusted desktop. |
| Remote-control/malware on phone | **Not prevented** | Phone compromise is an explicit nonclaim and deployment threat-model item. |
| Attestation certificate shared across personas | Kept non-portable | None attestation preferred; qualification evidence local only. |

## Browser secure-display qualification

A phone is physically separate from the compromised Linux compositor, so Hyprland cannot draw over it or inject its touch/biometric input. That establishes the needed platform separation only under the mobile threat model:

- other Linux processes cannot control the phone;
- no desktop-to-phone remote-control/accessibility bridge is trusted;
- the mobile OS isolates the A Quo browser origin;
- the browser renders the verified page faithfully;
- the authenticator performs genuine UV; and
- the enrolled phone-channel key/session remains unavailable to the Linux desktop.

Unlike a native app, a web client is fetched from an origin and can change between approvals. The design cannot claim a fixed audited client merely because one version was reviewed. Production qualification needs an update/downgrade policy and a way for authority and phone checkpoint state to reject security-incompatible client versions. A version string supplied only by JavaScript is not an attestation; the security claim still rests on origin integrity.

The browser should not use fullscreen as a trusted-path claim. Keeping visible browser origin UI is preferable. A home-screen PWA can improve product ergonomics but may hide origin and still receives web updates; it needs separate phishing/update analysis before being the sole supported presentation.

## Required controlled experiments

No actual phone model, OS version or browser support baseline was supplied, so these are material qualification experiments, not optional polish. They must use test personas, public keys and non-sensitive statements only.

### 1. WebAuthn raw-property matrix

**Question:** What do current supported iOS/iPadOS Safari and Android Chrome return for platform-passkey registration and authentication?

Record exact OS/browser/passkey-provider versions; raw bounded registration/assertion objects; algorithms; UP/UV; BE/BS; signCount; transports; attestation behavior; \`crossOrigin\`/\`topOrigin\`; cancellation and timeout. Test both built-in and intended alternative providers.

**Success:** every asserted policy field is available and independently verifiable; unsupported variants fail closed.  
**Failure:** required UV/origin/backup policy cannot be enforced.

### 2. Sync and desktop-use test

**Question:** Can a registered phone passkey be used from Chrome or another browser on the target Arch/Asahi Linux desktop under the same Apple/Google/provider account?

Try direct synced use and supported cross-device/hybrid flows. Compare accepted signed data from phone-page and desktop-originated ceremonies.

**Success:** the authority rejects every desktop-originated attempt because it lacks the phone channel, even where WebAuthn itself succeeds.  
**Failure:** a desktop can obtain both the exact challenge and a complete accepted result.

### 3. Phone-channel primitive test

**Question:** Can each supported browser create and persist a per-persona non-exportable channel key/session that is neither synchronized to the Linux browser nor silently re-created?

Test restart, OS/browser update, private-browsing exclusion, backup/restore, browser data clearing, credential-provider sync, multiple profiles and multiple personas. Inspect only test public keys and protocol outcomes.

**Success:** ordinary restart preserves the key; desktop cannot obtain/use it; clearing/restoration yields explicit loss or the documented safe state; no silent new binding.  
**Failure:** the key/session appears on another device, is replaced without recovery, or the browser cannot persist it.

### 4. Challenge secrecy and off-device ceremony test

**Question:** Can the untrusted coordinator/relay learn enough to invoke an accepted WebAuthn assertion from the desktop?

Capture all bytes visible to the desktop test process and relay. Attempt to reconstruct the challenge, access the phone mailbox as a desktop browser, substitute a desktop channel key and replay phone responses.

**Success:** desktop sees only ciphertext/locator and cannot create a channel-authenticated result.  
**Failure:** the fresh challenge or approval channel can be acquired before user approval.

### 5. Exact display/parser differential corpus

**Question:** Do authority and phone reconstruct exactly one semantic statement?

Use noncanonical encodings, duplicate/unknown fields, Unicode bidi/control characters, oversized values, alternate public-key encodings, signature order changes, truncation, clipping and separate-field substitution.

**Success:** identical canonical bytes and displayed semantics or fail closed.  
**Failure:** any accepted byte string has two renderings/meanings or an authoritative field can be hidden.

### 6. Origin and embedding test

**Question:** Does the authority reject lookalike origins, subdomains, related origins, iframes, unexpected top origins, service-worker downgrade and stale client versions?

**Success:** only the exact top-level origin and current profile are accepted.  
**Failure:** an alternate origin/client context produces an accepted result.

### 7. Lifecycle/race test

**Question:** What happens on phone lock, tab backgrounding, navigation, browser kill, network loss and authority cancel at every boundary?

Exercise before display, during display, during WebAuthn, after assertion, after channel signature, before authority receipt, after commit and before checkpoint acknowledgement.

**Success:** only a fully received, still-current exact result proceeds; every other state cancels or resolves idempotently.  
**Failure:** a late/stale result unlocks signing or a committed result forks.

### 8. Enrollment-substitution and replacement test

**Question:** Can desktop malware substitute authority, WebAuthn or channel keys during new-persona enrollment, migration or phone replacement?

**Success:** protected pairing detects every substitution and replacement requires all current/new authorities.  
**Failure:** a desktop-only QR/code or passkey login can create an accepted approval enrollment.

### 9. Persona-isolation test

**Question:** Does the origin create a shared deterministic link?

Inspect cookies, storage, server records, WebAuthn user handles, credential IDs, channel keys, analytics, push tokens and exported evidence for two unrelated test personas.

**Success:** independent per-persona state and no shared A Quo-created portable identifier.  
**Failure:** a shared account/cookie/device/installation field is required or exported.

### 10. Accessibility test

**Question:** Can all authoritative values be inspected and a deliberate WebAuthn-UV approval completed using VoiceOver, TalkBack, large text, zoom, switch control and external keyboard without an alternate approval bypass?

**Success:** equivalent complete display and final WebAuthn/channel authority; focus loss/clipping fails closed.  
**Failure:** a supported user cannot review/approve, or an accessibility-only signal becomes authority.

The first architecture gate is experiment 3. If no supported consumer phone browser can maintain the required phone-bound channel safely, normal synced passkeys alone do not provide a fallback. The browser profile is then blocked pending a general browser-bound-key primitive or a different approval application.

## Effect on issue #68

Issue #68 should **adopt this browser profile as the preferred focused approval-device candidate, conditional on the named phone-channel and browser-matrix experiments**.

It should not say:

- “passkeys provide trusted display”;
- “Face ID proves the statement was reviewed”;
- “platform authenticator means phone-only”;
- “BE=0 proves the assertion came from this browser”;
- “number matching authenticates the request”;
- “HTTPS alone makes the page a fixed audited client”; or
- “synced passkey recovery is approval-device recovery.”

It may truthfully say:

> Under the separate authority, signer and state assumptions, and while the enrolled phone OS, browser, fixed approval origin/client, passkey provider and per-persona phone channel remain trustworthy, ordinary malware confined to the Linux desktop cannot obtain a Tier 3 approval for different or undisplayed A Quo material. The phone client verifies and displays one authority-signed canonical request; an exact WebAuthn-UV assertion and phone-channel result bind approval to that request; the authority revalidates both before signer access. Desktop denial of service, deceptive proposals, phone/origin compromise and user coercion remain outside the claim.

The browser approach does not alter portable proof semantics. WebAuthn assertions and phone identifiers can remain local authority evidence; the portable receipt need bind only the approved semantic material and consent-result digest under the existing persona-specific authority enrollment. Offline proof verification remains possible.

## Proposed narrow \`re.md\` change plan

Do not edit until the owner accepts this investigation and the first feasibility gate is answered.

Only these sections need amendment:

1. **Section 1.1 (lines 35–48):** name the browser second-device profile as the preferred approval-device candidate, not a generic phone/passkey.
2. **Section 2 (Tier 3 claim):** add the approval origin/client, phone OS/browser/passkey provider and phone-channel assumptions and exclusions.
3. **Section 3.1–3.2 (component/edge map):** split the trusted phone client from the untrusted relay; specify encrypted authority request, WebAuthn assertion and channel-authenticated result.
4. **Section 4 (persona unlinkability):** define fresh per-persona WebAuthn credentials, random user handles, channel keys, no shared web account/session, local-only attestation and no portable WebAuthn fields.
5. **Section 4.2–4.3 (enrollment/replacement):** bind WebAuthn and phone-channel enrollment into the existing non-circular authority/persona authorization.
6. **Section 7–8 (ordering/idempotency):** add the secret challenge, phone prepared checkpoint, exact assertion/result replay and cancellation states without changing the sign-before-commit invariant.
7. **Section 9 operation traces:** replace generic “device” steps with the browser ceremony while retaining the same authoritative fields and migration signatures.
8. **Section 11.3 (consent/checkpoint):** define fixed origin/RP ID, trusted client, phone-channel primitive, full display, WebAuthn verification, checkpoint and loss/recovery.
9. **Section 11.4 (deployment lifecycle):** add origin/DNS/TLS/client release ownership, minimum browser/profile version and fail-closed downgrade behavior.
10. **Test-vector section:** add origin, cross-origin, synced credential, hybrid invocation, channel substitution, challenge disclosure, client downgrade, browser-state loss and cross-persona web-state vectors.
11. **Implementation decomposition:** put the phone/browser feasibility and closed consent protocol ahead of any Tier 3 claim or signer integration.
12. **Owner decisions:** replace “hardware versus phone” with the concrete origin operator, phone-channel primitive, supported OS/browser/provider matrix, enrollment route, multiple-device threshold and recovery choices.

No section should add wallet transaction signing, Plug & Prejudice, gpgv, package parsing or general proof parsing to the approval client.

## Decision gates

### Required before architecture acceptance

1. Select the exact per-persona phone-channel primitive and show that the Linux desktop cannot acquire or invoke it.
2. Select the exact fixed origin/RP ID and accept the origin/client/mobile TCB.
3. Define the non-circular initial pairing route.
4. Define phone checkpoint persistence, loss and rollback behavior.
5. Select minimum supported iOS/Android/browser/passkey-provider profiles from evidence.
6. Decide whether synced passkeys are permitted strictly as UV factors or whether Tier 3 requires a qualified BE=0 credential too.
7. Define planned replacement, lost-phone recovery and multiple-phone policy.
8. Establish per-persona browser/service isolation without a common correlator.

### Safe to defer to bounded implementation issues

- exact visual layout after authoritative field completeness is fixed;
- relay vendor/hosting implementation after its trust and metadata role is fixed;
- notification UX, provided notifications cannot approve or carry authoritative display fields;
- bounded request-number length, expiry and quotas;
- supported WebAuthn algorithms within a closed allow-list;
- optional local-only attestation profile;
- performance and offline queue limits; and
- non-authoritative desktop status presentation.

## Recommended next action

Conduct one focused, non-production browser feasibility prototype using only test personas and non-sensitive statements:

- current iOS Safari and Android Chrome;
- an ordinary synced passkey;
- a per-persona non-exportable browser channel key/session;
- authority-signed encrypted test envelopes;
- exact raw assertion verification; and
- the sync/hybrid, storage-loss, lifecycle and accessibility tests above.

Do not connect it to a signer or call it Tier 3. The go/no-go evidence is whether an accepted result always proves both (a) WebAuthn UV for the exact authority challenge and (b) possession of the independently enrolled phone channel, while the compromised Linux desktop sees neither usable capability.

If that passes, the phone URL workflow is the most practical current product direction and can replace the keypad candidate. If it fails because supported browsers cannot retain a safe phone-bound channel, generic passkeys do not repair it; issue #68 remains blocked pending a browser-bound primitive or a separately packaged approval application.

## Primary-source basis

### Specification guarantees

- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/): RP/origin scoping, signed client/authenticator data, assertion verification, UP/UV, BE/BS, counter limitations, attestation/privacy, code-injection and accessibility considerations.
- [Secure Payment Confirmation, 4 June 2026 Candidate Recommendation Draft](https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260604/): explicit statement that plain WebAuthn does not specify display of transaction data; payment-specific display and browser-bound-key work.

### Implementation-specific and ecosystem facts

- [Apple Passkeys](https://developer.apple.com/passkeys/): iCloud Keychain synchronization behavior.
- [Apple Platform Security — passkeys and iCloud Keychain](https://support.apple.com/en-ca/guide/security/sec1c89c6f3b/web): Apple credential synchronization/recovery architecture.
- [Google passkey support environments](https://developers.google.com/identity/passkeys/supported-environments): Google Password Manager synchronization and cross-device environment support.
- [Android passkeys](https://developer.android.com/identity/passkeys): Credential Manager/platform use and local device-unlock model.
- [FIDO moderate-assurance passkey guidance](https://fidoalliance.org/white-paper-fido-authentication-for-moderate-assurance-use-cases/) and [FIDO high-assurance guidance](https://fidoalliance.org/white-paper-high-assurance-enterprise-fido-authentication/): synced versus device-bound credential deployment considerations.

### Draft or unavailable as a baseline

- [Device Bound Session Credentials Editor's Draft](https://w3c.github.io/webappsec-dbsc/) and [Chrome origin trial](https://developer.chrome.com/blog/dbsc-origin-trial): promising device-bound web sessions, not a current cross-browser A Quo trusted-display guarantee.
- [Removal of unimplemented WebAuthn transaction-authorization extensions](https://github.com/w3c/webauthn/issues/1386): no current general \`txAuth\` display primitive.

### Inferences

- A correctly isolated phone display/input path is outside the ordinary Linux desktop UID's graphical and input control.
- Encrypting the fresh authority challenge to a separately enrolled phone channel prevents a synced desktop credential from being used to approve, provided the phone channel and origin are uncompromised.
- A remote relay can be reduced to availability/metadata risk when it receives only authenticated ciphertext and the authority verifies all final cryptographic objects.

### Unestablished target facts

- supported phone models, OS versions, browsers and passkey providers;
- availability of useful BE=0 platform credentials on those phones;
- whether such credentials permit indistinguishable hybrid/off-device assertions;
- persistent non-synced browser channel-key behavior across each platform's backup/update lifecycle;
- exact per-persona web-storage isolation UX;
- complete VoiceOver/TalkBack/switch-control behavior; and
- production support/status of general browser-bound session-key mechanisms.

## Final state

- \`origin/main\` reviewed: \`a10a371f2bed300a78beabc72f58bf27abc31b8d\`
- current branch at investigation time: \`issue-65-prepare-isolated-gpgv-runtime\`
- current HEAD at investigation time: \`bd139ffe48a5c2834698a82e4d0c94394b81d6f7\`
- \`re.md\` remained untracked and was not edited; SHA-256: \`0386ec2df46e731408fd120109b204ffcbe60bef3d876368d873ccfadf7f7539\`
- \`report2.md\` remained untracked and was not edited; SHA-256: \`0c6cf54152e329e7a054a48f044af75bc547236a38db79c9821b0d621941856e\`
- only \`report3.md\` was intentionally created
- no tracked repository file, branch, commit, GitHub object, Project field or system configuration was changed
- final feasibility verdict: **BROWSER-SECOND-DEVICE-CONDITIONALLY-FEASIBLE**
- unresolved architecture gates before issue-#68 acceptance: 8
- required focused target experiment groups: 10
