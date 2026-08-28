# Consent IPC decision

**Status:** accepted for the Linux/Omarchy implementation  
**Date:** 2026-08-28

## Decision

A Quo will not place signing or consent authority on D-Bus. The Linux daemon
will expose a direct per-user Unix `SOCK_SEQPACKET` socket at a validated path
under `XDG_RUNTIME_DIR`. Its protocol is specific to A Quo, closed, bounded,
versioned, and tested with hostile inputs.

Each connection carries one request and one terminal response. The request has:

- fixed magic, major/minor version, message type, flags, and payload length;
- fixed fields for the selected local persona and inert display context;
- no variants, dictionaries, arbitrary method names, introspection, broadcasts,
  object registration, or “options” extension map; and
- exactly one artifact descriptor delivered out of band with `SCM_RIGHTS`.

Unknown versions, message types, flags, extra descriptors, oversized fields,
invalid UTF-8, control/bidirectional display characters, and trailing bytes are
fatal protocol errors. The socket directory is mode 0700 and the socket mode
0600. The daemon checks Linux `SO_PEERCRED` and rejects a different UID.

Peer UID/PID are evidence about the connection, not permission to sign. Any
same-user process can ask. The daemon serializes requests, creates a bounded
memfd snapshot, seals it against writes/growth/shrinkage, computes the digest,
and asks a separate trusted GTK/libadwaita process to approve that exact
persona, purpose, size, digest, and caller evidence. Only the daemon invokes the
configured signer. It returns a proof or typed rejection, never key material.

Closing the connection cancels an unapproved request. Prompts and signer calls
have fixed deadlines. Logs contain request IDs, decisions, and non-sensitive
evidence only—never artifact content, private keys, wallet credentials, or
recovery material.

## Why not D-Bus

D-Bus is useful for desktop interoperability, but its generic session bus adds
discovery, object naming, flexible signatures, policy machinery, and a large
API surface that this security boundary does not need. Session-bus reachability
would not authorize a signature, and a bus name would not establish a stable
caller identity.

This concern is well summarized in Vaxry's critique of permissive protocols and
permission defaults: [D-Bus is a disgrace to the Linux desktop](https://blog.vaxry.net/articles/2025-dbusSucks).
The decision does not require agreeing with every claim in that article; A Quo
simply has a narrower problem for which a direct capability-bearing channel is
easier to specify, test, and audit.

## Why not require hyprtavern or hyprwire yet

[Hyprwire](https://github.com/hyprwm/hyprwire) has the strict-protocol direction
A Quo wants and now has a pure-Rust implementation. It remains young, while
[hyprtavern](https://github.com/hyprwm/hyprtavern) explicitly describes itself
as early development with a protocol that is not yet fixed. Hyprtavern also
correctly states that a per-user bus is not a boundary against unrestricted
same-user processes.

A Quo therefore will not make either project a security-critical dependency
today. A future adapter may advertise or discover the A Quo socket through
hyprtavern. The actual request, file descriptor, consent decision, and proof
will continue over the direct authenticated socket.

## Alternatives and revisit conditions

- **D-Bus:** rejected for the authority path; may be used only by unrelated
  desktop components where compromise cannot approve a signature.
- **Hyprtavern-routed authority:** deferred until its protocol, permission model,
  Rust story, descriptor passing, release lifecycle, and audit posture stabilize.
- **Hyprwire direct transport:** promising but unnecessary for the small v1
  message set; reconsider if maintaining our strict codec becomes riskier than
  adopting its reviewed Rust implementation.
- **Plain paths or JSON over a stream socket:** rejected because mutable paths
  create review/sign races and streams add framing ambiguity. Human-readable
  JSON may be used only inside tests or non-authoritative diagnostics.

Revisit this decision after a security review, or when a cross-desktop standard
offers strict schemas, capability-style descriptor passing, stable peer
identity, and deny-by-default permissions without weakening the consent model.
