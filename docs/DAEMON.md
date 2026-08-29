# Private signing daemon

## Current status

The Linux daemon foundation is implemented. It binds a direct per-user Unix
`SOCK_SEQPACKET` socket, receives the strict A Quo protocol, snapshots the
purpose-specific input, applies persona/key policy, asks an approval backend,
signs only after approval, and returns a sealed proof descriptor. Artifact,
domain-control, persona-root, and routine persona-transition requests use
separate closed message types and SSHSIG namespaces.

The routine-transition path is a bounded prototype for newly daemon-journaled
live histories, including a history whose latest entry is an explicitly
committed recovery transition. It constructs the canonical statement from the
local authoritative mixed journal, requires both the old and proposed keys to
sign the same bytes, and commits the proof and local key handoff before
releasing the proof. It is not release-ready: independent review, packaging,
accessible consent, older-history or evidence-archive adoption, and trusted
multi-party recovery consent remain outstanding. Recovery-policy recording and
recovery-transition or terminal-revocation commit are explicit CLI/store
workflows; they are not daemon consent message types. Terminal revocation has
no successor signer to challenge and currently adopts threshold-signed evidence
without claiming a trusted multi-party ceremony. Adding it to trusted consent
requires a separately reviewed multi-party design rather than widening the
single-user daemon protocol.

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

Every approval receives the persona ID/label/purpose, public-key fingerprint,
request UUID, and peer UID/GID/PID. An artifact prompt also receives the
caller-supplied kind and label plus exact SHA-256/size. A domain prompt instead
receives the exact canonical DNS name, derived TXT commitment, and validity
window. A persona-root prompt receives the unique anchor, root-statement digest,
and issuance time. A routine-transition prompt receives the persona anchor,
pinned root digest, sequence, prior chain-head digest when present, issuance
time, previous and next key fingerprints, and exact transition-statement
digest. It receives neither input contents nor signer paths or key material.
Artifact kind and label are display context and do not enlarge the generic
artifact claim in proof v1. Domain control is a separate, short-lived claim and
never means legal ownership or registrant identity. Persona-root approval
establishes local intent to create that self-asserted, correlating root; it does
not establish external pinning, legal identity, or recovery. Transition
approval establishes local intent for that exact key-continuity statement; it
does not establish legal identity, current authorization, or key safety.

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
A Quo prompt, artifact digest, or persona data. The signer environment does not
contain `DBUS_SESSION_BUS_ADDRESS`.

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
**Rotate key**.

The transition review is fixed at 780 by 900 logical pixels in this prototype.
Approval remains unavailable unless both the window and a known current output
can contain the complete review at their current scale. On an unknown, smaller,
or heavily scaled output, the UI shows a fail-closed notice and exposes only
decline/cancel behavior; keyboard or pointer input cannot arm or activate
approval. This size gate prevents approval of clipped transition evidence only.

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
text.

The standalone binary logs only request UUID (when one exists), approved or
rejected outcome, and failure class. It does not log artifact bytes, private
keys, signer paths, wallet data, recovery material, or raw proof contents.
