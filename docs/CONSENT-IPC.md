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
- fixed fields for one closed signing purpose; local-persona operations carry a
  canonical persona UUID, while recovery participation intentionally does not;
- no variants, dictionaries, arbitrary method names, introspection, broadcasts,
  object registration, or “options” extension map; and
- exactly one purpose-specific input descriptor delivered out of band with
  `SCM_RIGHTS`.

## Implemented v1 wire format

Every integer uses network byte order. The 20-byte header is:

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 8 | `AQUOIPC\0` magic |
| 8 | 2 | major version (`1`) |
| 10 | 2 | minor version (`0`) |
| 12 | 2 | message type |
| 14 | 2 | flags (must be zero) |
| 16 | 4 | payload length |

A type-1 signing request carries a six-byte fixed prefix: artifact-kind byte,
zero reserved byte, persona-ID byte length, and artifact-label byte length. The
two UTF-8 values follow with no terminators. Persona IDs must be canonical
lowercase UUIDs. The complete request is at most 346 bytes and must carry
exactly one descriptor received with close-on-exec semantics.

Artifact kind is a closed display hint: generic (`1`), software release (`2`),
article (`3`), or image (`4`). It does not change or enlarge the cryptographic
claim in the v1 generic-artifact statement.

A type-4 domain-control signing request carries a four-byte fixed prefix: the
persona-ID byte length followed by two zero reserved bytes. The canonical UUID
follows with no terminator. The complete request is at most 88 bytes and must
carry exactly one regular-file descriptor containing an unsigned canonical
domain-control statement of at most 4 KiB. Domain control is a distinct message
and signed-statement namespace; it is not an artifact display kind.

A type-5 persona-root signing request uses the same closed four-byte
persona-only layout and 88-byte packet ceiling. Its one descriptor contains an
unsigned RFC 8785 persona-root statement of at most 64 KiB. Persona-root
signing has its own message type, proof schema, and SSHSIG namespace; it cannot
fall through the generic artifact or domain paths.

A type-6 routine persona-transition request has an 80-byte fixed prefix followed
by the persona ID and proposed signer locator:

| Payload offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | proposed key provider (`1` OpenSSH file, `2` SSH agent, `3` FIDO2) |
| 1 | 1 | previous-transition-digest presence (`0` absent, `1` present) |
| 2 | 2 | reserved; zero |
| 4 | 4 | expected transition sequence; nonzero |
| 8 | 2 | persona-ID byte length |
| 10 | 2 | proposed signer-locator byte length |
| 12 | 4 | reserved; zero |
| 16 | 32 | raw expected persona-root statement SHA-256 |
| 48 | 32 | raw expected prior-transition SHA-256, or all zero when absent |
| 80 | variable | persona ID, then proposed signer locator |

The persona ID is at most 64 bytes. The locator is nonempty absolute UTF-8,
rejects leading/trailing whitespace, controls, Unicode line/paragraph
separators, and Unicode 17.0 default-ignorable characters, and is at most 4,096
bytes. Sequence 1 requires no prior digest; later sequences require one. The
maximum type-6 payload is 4,240 bytes, or 4,260 bytes including the header. Its
one descriptor must be a nonempty regular file containing at most 16 KiB of
proposed OpenSSH public-key text. The descriptor contains no private key or
transition statement: the daemon derives the statement from its verified
journal.

A type-7 recovery-participation request has a 120-byte fixed prefix followed by
the participant's local signer locator and normalized OpenSSH public key:

| Payload offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | participant provider (`1` OpenSSH file, `2` SSH agent, `3` FIDO2) |
| 1 | 1 | previous-head-digest presence (`0` absent, `1` present) |
| 2 | 2 | reserved; zero |
| 4 | 4 | policy version derived from the independently pinned policy |
| 8 | 4 | policy threshold derived from the independently pinned policy |
| 12 | 4 | independently expected previous-head sequence |
| 16 | 2 | local signer-locator byte length |
| 18 | 2 | participant-public-key byte length |
| 20 | 4 | reserved; zero |
| 24 | 32 | raw expected persona-root statement SHA-256 |
| 56 | 32 | raw expected latest-policy statement SHA-256 |
| 88 | 32 | raw expected previous-head SHA-256, or all zero when absent |
| 120 | variable | local signer locator, then participant public key |

This message has no persona UUID. Its private local locator is nonempty,
absolute, bounded at 4,096 bytes, and subject to the same unsafe-display and
path validation used at the signer boundary. The public key is bounded at 16
KiB. The maximum type-7 payload is 20,600 bytes, or 20,620 bytes including the
header. Its one descriptor must be a nonempty, fully sealed regular file
containing the exact canonical portable recovery-ceremony request, bounded at
8 MiB. The portable request and returned response contain no signer locator or
persona UUID.

A type-2 approved response has an empty payload and exactly one descriptor
containing the portable proof or recovery response. That descriptor must be a
nonempty regular file, at most 1 MiB, with Linux `F_SEAL_SEAL`,
`F_SEAL_SHRINK`, `F_SEAL_GROW`, and `F_SEAL_WRITE` present. A type-3 rejection
has a four-byte payload containing a closed two-byte reason code and two zero
reserved bytes; it carries no descriptor and no arbitrary text. The closed
reasons include a distinct `consent_unavailable` result for a missing or failed
trusted approval process.

The Linux implementation rejects packet or ancillary truncation, zero or extra
descriptors, unknown ancillary messages, partial sends, invalid UTF-8, unsafe
display controls, noncanonical UUIDs, incorrect inner or outer lengths, and all
unknown enum values.

## Immutable request snapshot

The ordinary snapshot primitive accepts only an already-open regular-file
descriptor and copies it into a new memfd while computing SHA-256 and byte
length. Artifact requests allow at most 512 MiB; domain statements allow at
most 4 KiB; persona-root statements allow at most 64 KiB; and routine-
transition public-key inputs allow at most 16 KiB and must be nonempty. The
recovery client snapshots and seals the exact canonical request under an 8 MiB
limit before sending it; the daemon rejects that descriptor unless all four
seals are already present. Snapshot construction uses positional reads rather
than the descriptor's shared seek offset,
so a caller cannot steer the snapshot by seeking concurrently. It then applies
and re-reads all four immutability seals before exposing the snapshot. Changes
to the caller's source afterward cannot alter the bytes reviewed or signed. A
deployment may choose lower limits but cannot raise these hard maxima.

For a domain request, the sealed bytes must be the one canonical JSON encoding
of the supported statement schema. Before approval, the daemon verifies its
domain, nonce, lifetime, selected persona label, and selected public-key
fingerprint, then derives the exact DNS TXT commitment. Alternate whitespace or
field ordering is rejected even when it would decode to the same JSON value.

For a persona-root request, the daemon accepts only exact RFC 8785 bytes. It
binds the root to the selected persona label and active public-key fingerprint,
requires issuance within five minutes of its clock, and derives the exact root
statement SHA-256 shown for consent. It repeats that review after approval,
immediately before signing.

For a routine-transition request, the daemon normalizes and fingerprints the
proposed public key, reverifies the complete local routine journal, and checks
the expected root, sequence, prior head, closed provider, and canonical signer
locator. It constructs the canonical statement rather than accepting statement
bytes from the caller. After approval it repeats the journal and signer checks,
requires both old and new keys to sign the identical statement, verifies the
resulting complete chain, and atomically commits the proof and key handoff
before returning it. An exact retry may recover that committed proof after a
lost response; altered intent is not a retry.

For a recovery-participation request, the daemon parses only exact RFC 8785
request bytes, reverifies the complete embedded root, policy chain, mixed
transition history, candidate, signed ceremony ID/expiry, and the root/latest-
policy/previous-head pins supplied in the type-7 packet. Each full
reverification pass caps aggregate embedded signature-verification work at
2,048 before cryptographic SSHSIG verification; pre-consent and post-consent
passes remain separate work.
The participant's role is derived from their normalized key, the transition
namespace follows that role, and request binding uses a fixed separate
namespace; the caller cannot select any of them. The daemon obtains direct
consent, rechecks the request, pins, clock, and signer target, then creates both
the existing transition-statement signature and a purpose-separated signature
over the exact canonical request. It self-verifies both before returning the
sealed canonical response. A FIDO participant may need two physical touches.
No store is mutated by participation.

Unknown versions, message types, flags, extra descriptors, oversized fields,
invalid UTF-8, unsafe display characters, and trailing bytes are fatal protocol
errors. The socket directory is mode 0700 and the socket mode 0600. The daemon
checks Linux `SO_PEERCRED` and rejects a different UID.

Peer UID/PID are evidence about the connection, not permission to sign. Any
same-user process can ask. The daemon serializes requests, creates a bounded
memfd snapshot, seals it against writes/growth/shrinkage, computes the digest,
and asks a separate direct-Wayland process to approve the exact purpose-specific
evidence. Artifact prompts show persona, kind, size, digest, label, and caller
evidence. Domain prompts show persona, exact DNS name, exact TXT value, validity
window, and caller evidence. Persona-root prompts show persona, unique anchor,
root-statement digest, issuance time, key, and caller evidence. Routine
transition prompts show persona and anchor, pinned root, sequence, prior chain
head, issuance time, old and new key fingerprints, exact transition-statement
digest, and caller evidence. Recovery-participation prompts show the verified
persona and anchor, signed ceremony ID and expiry, derived role and participant
fingerprint, root/policy/head pins, reason, old and successor fingerprints,
exact request digest, and caller evidence across two fixed pages. They contain
no coordinator-local persona UUID or participant signer locator. Daemon and UI
use inherited pipes and the separate closed `AQUOAPR` protocol; neither
approval request nor decision traverses a bus. Only the daemon invokes the
configured signer. It returns a proof or typed rejection, never key material.

Closing the connection cancels an unapproved request. The daemon revalidates
the active persona, key, and signing reference after approval and again after
the signer returns. For routine rotation it also revalidates the journal and
candidate signer after approval, commits before response, and permits only an
exact committed-proof retry. Prompts and signer calls have fixed deadlines.
Logs contain request IDs, decisions, and non-sensitive evidence only—never
artifact content, private keys, wallet credentials, or recovery material.

The daemon-to-UI pipe format is specified in
[One-shot approval protocol](APPROVAL-PROTOCOL.md).

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
