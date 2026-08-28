# Private signing daemon

## Current status

The Linux daemon foundation is implemented. It binds a direct per-user Unix
`SOCK_SEQPACKET` socket, receives the strict A Quo protocol, snapshots the
artifact, applies persona/key policy, asks an approval backend, signs only after
approval, and returns a sealed proof descriptor.

The GTK4/libadwaita approval backend is the next layer and is not wired yet.
The current `a-quo-daemon` binary deliberately uses an unavailable backend, so
every otherwise valid request receives `consent_unavailable`. There is no
command-line auto-approve option and no D-Bus authority path.

## Request flow

For each connection, the daemon:

1. checks `SO_PEERCRED` and accepts only the current UID;
2. receives one bounded packet and exactly one close-on-exec artifact FD;
3. rejects a closed connection or illegal second packet;
4. resolves exactly one active key and its revalidated signer reference;
5. copies a regular file into a bounded, sealed memfd and derives its digest;
6. constructs a fresh request UUID and inert approval prompt data;
7. asks the separate trusted approval backend;
8. rechecks that the client is still waiting before invoking the signer;
9. creates and self-verifies the SSHSIG proof against the registered public key;
10. seals the proof in another memfd and returns that FD; and
11. closes the one-request connection.

Approval receives the persona ID/label/purpose, public-key fingerprint,
caller-supplied artifact kind and label, exact SHA-256/size, request UUID, and
peer UID/GID/PID. It receives neither artifact contents nor signer paths or key
material. Artifact kind and label are display context and do not enlarge the
generic artifact claim in proof v1.

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
requests serially so approval prompts cannot overlap. OpenSSH signing and
verification each have a 120-second deadline. The future approval process must
also enforce its own fixed deadline.

## Failure reporting and logs

Clients receive only a closed reason code: invalid request, cancelled, persona
unavailable, consent unavailable, user declined, signer unavailable, or
internal error. They never receive raw filesystem, database, signer, or UI error
text.

The standalone binary logs only request UUID (when one exists), approved or
rejected outcome, and failure class. It does not log artifact bytes, private
keys, signer paths, wallet data, recovery material, or raw proof contents.
