# Private signing daemon

## Current status

The Linux daemon foundation is implemented. It binds a direct per-user Unix
`SOCK_SEQPACKET` socket, receives the strict A Quo protocol, snapshots the
purpose-specific input, applies persona/key policy, asks an approval backend,
signs only after approval, and returns a sealed proof or response descriptor.
Artifact, domain-control, persona-root, routine persona-transition, and
recovery-transition participation requests use separate closed message types
and purpose-separated SSHSIG namespaces.

The routine-transition path is a bounded prototype for newly daemon-journaled
live histories, including a history whose latest entry is an explicitly
committed recovery transition. It constructs the canonical statement from the
local authoritative mixed journal, requires both the old and proposed keys to
sign the same bytes, and commits the proof and local key handoff before
releasing the proof. It is not release-ready: independent review, packaging,
accessible consent, and older-history or evidence-archive adoption remain
outstanding.

The type-7 recovery-participation path is a separate bounded prototype. It lets
one policy authority or the named successor independently verify and consent to
one portable, full-evidence recovery-transition request. The daemon derives the
participant's role from their key and returns a canonical response containing
two purpose-separated signatures: the existing signature over the transition
statement and a second signature binding that participant to the exact
canonical request. It does not assemble the threshold proof, mutate a persona
store, commit the transition, or activate imported evidence.

This path covers recovery-transition participation only. Recovery-policy
enrolment and update, and terminal revocation, remain sequential CLI/store
workflows without equivalent distributed consent ceremonies. The low-level
`recovery-transition-create` command also remains available and does not use
the trusted local ceremony-participation path. Neither path proves that the
keys are held by different people or devices. Packaging, complete
accessibility, independent review, and broader real-world ceremony testing
remain release work.

The direct-Wayland approval backend and its one-shot child protocol are
implemented. The daemon enables them only when
`/usr/lib/a-quo/a-quo-consent` and every path component are root-owned,
non-symlink, and not group/world-writable. Otherwise every valid request gets
`consent_unavailable`. There is no command-line override, auto-approve option,
or D-Bus authority path.

## Request flow

For an artifact, domain-control, or persona-root connection, the daemon:

1. checks `SO_PEERCRED` and accepts only the current UID;
2. receives one bounded packet and exactly one close-on-exec input FD;
3. rejects a closed connection or illegal second packet;
4. resolves exactly one active key and its revalidated signer reference;
5. positionally copies a regular file into a purpose-bounded, sealed memfd and
   derives its digest without trusting the shared FD offset;
6. validates the exact artifact descriptor, canonical domain statement, or
   canonical fresh persona-root statement and constructs a fresh request UUID
   plus inert approval prompt data;
7. asks the separate trusted approval backend;
8. rechecks that the client is still waiting and that signer policy is unchanged;
9. creates and self-verifies the purpose-separated SSHSIG proof against the
   registered public key and the evidence that was approved;
10. rechecks signer policy after the possibly interactive signer returns;
11. seals the proof in another memfd and returns that FD; and
12. closes the one-request connection.

For a routine transition, the one descriptor contains only the proposed
OpenSSH public-key text and is snapshotted with a 16 KiB ceiling. The daemon
reverifies the complete root, recovery-policy chain when present, and tagged
routine/recovery journal. A terminally revoked persona has no active signer and
is rejected before this path. For an operational history the daemon checks the
caller-supplied root digest,
expected sequence and prior head, current signer, proposed provider, public key,
and canonical signer locator, and constructs the canonical transition itself.
After direct consent it repeats those state and signer checks, has both keys
sign identical statement bytes, verifies both signatures and the complete
resulting chain, then uses one immediate SQLite transaction to retire the old
key, activate and bind the new key, append lifecycle and proof rows, and
compare-and-swap the head. It rereads and reverifies the committed result before
sealing and returning it.

If a connection interruption is detected before commit, the request cancels
without advancing the head. If commit races with a disconnect or succeeds but
the response is lost, an exact retry can return the already committed public
proof without another consent or signature. The retry must match the root,
sequence, prior head, proposed public key, provider, and stored signer locator;
a different request is a conflict and fails closed. The local SQLite journal is
crash-consistent context, not an independent witness or proof that the caller
obtained the root pin separately.

For recovery participation, the type-7 packet supplies the participant's local
provider, absolute signer locator, normalized public key, and independently
expected root, latest-policy, and previous-head checkpoints. It has no persona
UUID. Its one descriptor is an already sealed, bounded canonical request
containing the complete signed root, ordered policy chain, prior mixed
transition history, those checkpoints, the candidate schema-v2 recovery
transition, and successor public key. The portable request contains neither a
persona UUID nor a signer locator.

The daemon reverifies that complete request, including its signed random
ceremony ID and strict expiry. Each full verification pass caps aggregate
embedded signature-verification work at 2,048 before processing the embedded
structures or performing cryptographic SSHSIG verification; the daemon performs
separate passes before and after consent. It matches the independently supplied
checkpoints, derives whether the participant is an authorized policy authority
or the exact successor from the supplied key, and asks for direct Wayland
consent. After consent it rechecks the request, checkpoints, clock, and signer
target. The same authorized key then signs both the transition statement under
its derived role namespace and the exact canonical request under
`a-quo-persona-recovery-ceremony-request-v1`; the daemon self-verifies both
signatures before returning a sealed canonical response. A FIDO-backed signer
may therefore require two physical touches.

Starting, responding, and deterministic assembly remain non-mutating file
steps. Assembly places only the existing role-specific transition signatures
into the existing recovery-proof wrapper; live
`recovery-transition-commit` or archive `backup-activate-recovery` is a
separate operation. Responding and assembly must precede the signed expiry, as
must the first authority-creating live commit or archive activation. Exact
replay of an already committed live transition or a sealed archive-activation
receipt may succeed after expiry because it grants no new authority; the store
revalidates the recorded first-use time and does not invoke a signer.

The per-pass work cap does not make the serialized same-UID service resistant
to every resource-exhaustion strategy. Rate control and broader hostile-request
testing remain hardening work.

Every approval receives a request UUID and peer UID/GID/PID. Ordinary
local-persona approvals also receive the persona ID/label/purpose and public-key
fingerprint. An artifact prompt receives the caller-supplied kind and label
plus exact SHA-256/size. A domain prompt instead receives the exact canonical
DNS name, derived TXT commitment, and validity window. A persona-root prompt
receives the unique anchor, root-statement digest, and issuance time. A
routine-transition prompt receives the persona anchor, pinned root digest,
sequence, prior chain-head digest when present, issuance time, previous and
next key fingerprints, and exact transition-statement digest.

A recovery-participation prompt uses two fixed pages. It receives the verified
persona label and anchor, signed ceremony ID and expiry, participant role
derived from the key, participant fingerprint, independently supplied
root/latest-policy/previous-head checkpoints, recovery reason, old and
successor fingerprints, and exact canonical-request digest. It receives no
coordinator-local persona UUID, participant signer locator, input secrets, or
key material.

Artifact kind and label are display context and do not enlarge the generic
artifact claim in proof v1. Domain control is a separate, short-lived claim and
never means legal ownership or registrant identity. Persona-root approval
establishes local intent to create that self-asserted, correlating root; it does
not establish external pinning, legal identity, or recovery. Transition
approval establishes local intent for that exact key-continuity statement; it
does not establish legal identity, current authorization, or key safety.
Recovery participation establishes local intent to make both signatures for
that exact request and transition statement. It does not prove holder or device
independence, trusted time, hardware use, legal identity, or that later
assembly or adoption occurred.

## Runtime socket

By default the daemon uses `$XDG_RUNTIME_DIR/a-quo/consent.sock`. It requires an
absolute, current-user-owned, non-symlink runtime directory with no group/world
permissions. The A Quo directory is mode 0700 and the socket is mode 0600.

The listener refuses every pre-existing socket-path entry. On normal teardown,
it removes the path only if it is still the same owned socket inode; it will not
remove a replacement file. An abrupt kill can leave a stale socket. Until
systemd user socket activation or signal-aware cleanup is packaged, an operator
must first confirm that no daemon owns it before removing that exact stale path.

Connections get fixed 10-second send and receive timeouts. The daemon processes
requests serially so approval prompts cannot overlap. The UI cancels at 90
seconds, the parent kills and reaps it at 95 seconds, and OpenSSH signing and
verification each have a 120-second deadline. OpenSSH and any child it starts
run in a separate process group that is killed and reaped on failure or timeout.

An encrypted file or hardware-backed key may cause OpenSSH to show a separate
operating-system askpass/PIN prompt after A Quo consent. That prompt unlocks the
selected key; it is not authority to approve the signature, and it receives no
A Quo prompt, artifact digest, or persona data. Recovery participation performs
two signer operations over different exact bytes, so a hardware-backed signer
may prompt or require a touch twice. The signer environment does not contain
`DBUS_SESSION_BUS_ADDRESS`. PIN entry and physical-touch requests are conveyed
through the configured trusted askpass or hardware-device UI, not through
unstructured signer output.

## Approval subprocess

The daemon clears the child's environment and restores only Wayland runtime
and locale settings. It does not pass `DBUS_SESSION_BUS_ADDRESS`,
`DISPLAY`, `PATH`, loader overrides, SSH agent variables, or signer data. The
child reads one bounded binary prompt from stdin and returns exactly one
approve, decline, or cancel message on stdout, bound to the request UUID.
The byte layout is documented in
[One-shot approval protocol](APPROVAL-PROTOCOL.md).

The UI is a Wayland-only `winit` client rendered through `softbuffer`,
`tiny-skia`, and direct `swash` shaping/rasterization backed by `skrifa`.
Default features are disabled, and its active dependency graph contains no
D-Bus, portal, GTK/GIO, AT-SPI, Fontconfig, font database, or `ttf-parser`
crate. It uses a fixed dark theme and undecorated surface, so `winit` does not
perform its optional D-Bus theme lookup. A packaged root-owned system font is
loaded from a closed path list; every path component is checked before the font
is read.

Approval starts disabled. For artifacts, the user must arm a digest-specific
confirmation and then activate **Sign bytes**. For domain control, the user must
arm a confirmation bound to the exact name and TXT commitment and then activate
**Sign claim**. For a persona root, the user must arm a confirmation bound to
the unique anchor and root digest and then activate **Create root**. For a
routine transition, the user must review both key fingerprints and the exact
transition digest, arm the transition-specific confirmation, and activate
**Rotate key**. For recovery participation, the user must review both evidence
pages, arm a confirmation covering the exact request and transition, and
activate **Sign response**.

The routine-transition and recovery-participation reviews are fixed at 780 by
900 logical pixels in this prototype. Approval remains unavailable unless both
the window and a known current output can contain the complete review at their
current scale. On an unknown, smaller, or heavily scaled output, the UI shows a
fail-closed notice and exposes only decline/cancel behavior; keyboard or pointer
input cannot arm or activate approval. This size gate prevents approval of
clipped transition evidence only.

The consent window is an ordinary Wayland `xdg_toplevel`; it has no
secure-attention, exclusive-display, or trusted-overlay guarantee. Another
same-session Wayland or layer-shell client may overlay, occlude, imitate, or
otherwise confuse the prompt without first causing a focus-loss event. The
prototype therefore assumes a trusted compositor and display path. A
compositor-protected consent surface or equivalent secure-attention design,
plus responsive and accessible review, remains release work.

Decline has initial focus. Escape, close, and expiry cancel; losing focus
disarms confirmation, clears an in-progress click, and restores focus to
Decline.

## Failure reporting and logs

Clients receive only a closed reason code: invalid request, cancelled, persona
unavailable, consent unavailable, user declined, signer unavailable, or
internal error. They never receive raw filesystem, database, signer, or UI error
text. In particular, raw `ssh-keygen` stderr is suppressed because it may
contain the private signer locator. Typed, redacted failures and the child exit
status remain available, but detailed child diagnostics are intentionally not
returned or journaled; interactive PIN or touch feedback belongs to the trusted
askpass or device UI.

The standalone binary logs only request UUID (when one exists), approved or
rejected outcome, and failure class. It does not log artifact bytes, private
keys, signer paths, wallet data, recovery material, or raw proof contents.
