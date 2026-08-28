# One-shot approval protocol

**Status:** implemented v1
**Transport:** inherited stdin/stdout pipes
**Authority:** daemon-to-packaged-consent-process only

`AQUOAPR` is deliberately not a service protocol. The signing daemon starts one
root-owned consent process for one prompt, writes one message to its stdin,
closes stdin, reads one response from stdout, and reaps the process. There is no
socket name, discovery mechanism, method registry, broadcast, variant, option
map, or D-Bus object.

## Common header

Every integer uses network byte order. Each message starts with this 20-byte
header:

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 8 | `AQUOAPR\0` magic |
| 8 | 2 | major version (`1`) |
| 10 | 2 | minor version (`0`) |
| 12 | 2 | message type |
| 14 | 2 | flags (must be zero) |
| 16 | 4 | payload length |

Readers reject an unknown version, type, flag, oversized payload, truncated
payload, or any byte after the declared payload. Pipe EOF is part of framing.

## Artifact prompt

Message type `1` has a 96-byte fixed prefix followed by three UTF-8 strings:

| Payload offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | artifact kind (`1` generic, `2` software, `3` article, `4` image) |
| 1 | 1 | persona purpose (`1` personal through `5` legal bridge) |
| 2 | 2 | reserved; zero |
| 4 | 4 | caller PID; nonzero |
| 8 | 4 | caller UID |
| 12 | 4 | caller GID |
| 16 | 8 | immutable artifact byte length |
| 24 | 16 | request UUID bytes; non-nil |
| 40 | 16 | persona UUID bytes; non-nil |
| 56 | 32 | raw SHA-256 digest |
| 88 | 2 | persona-label byte length |
| 90 | 2 | key-fingerprint byte length |
| 92 | 2 | artifact-label byte length |
| 94 | 2 | reserved; zero |
| 96 | variable | persona label, then fingerprint, then artifact label |

Persona and artifact labels are nonempty and at most 256 UTF-8 bytes each. The
fingerprint is at most 128 bytes and must use canonical unpadded OpenSSH
`SHA256:` form. All display strings reject leading/trailing whitespace,
controls, and Unicode bidirectional-formatting characters. The maximum artifact
prompt is 736 payload bytes or 756 bytes including the header.

## Domain-control prompt

Message type `5` has a 76-byte fixed prefix followed by four UTF-8 strings:

| Payload offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | persona purpose (`1` personal through `5` legal bridge) |
| 1 | 3 | reserved; zero |
| 4 | 4 | caller PID; nonzero |
| 8 | 4 | caller UID |
| 12 | 4 | caller GID |
| 16 | 8 | issued-at Unix time; signed big-endian integer |
| 24 | 8 | expires-at Unix time; signed big-endian integer |
| 32 | 16 | request UUID bytes; non-nil |
| 48 | 16 | persona UUID bytes; non-nil |
| 64 | 2 | persona-label byte length |
| 66 | 2 | key-fingerprint byte length |
| 68 | 2 | canonical-domain byte length |
| 70 | 2 | DNS-TXT-value byte length |
| 72 | 4 | reserved; zero |
| 76 | variable | persona label, fingerprint, domain, then TXT value |

The domain is canonical lowercase ASCII DNS form and at most 253 bytes. The
TXT value is the exact canonical `a-quo-domain-v1=` commitment and at most 128
bytes. Expiry must follow issuance by no more than 30 days. The maximum domain
prompt is 841 payload bytes or 861 bytes including the header.

## Persona-root prompt

Message type `6` has a 96-byte fixed prefix followed by three UTF-8 strings:

| Payload offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 1 | persona purpose (`1` personal through `5` legal bridge) |
| 1 | 3 | reserved; zero |
| 4 | 4 | caller PID; nonzero |
| 8 | 4 | caller UID |
| 12 | 4 | caller GID |
| 16 | 8 | issued-at Unix time; signed big-endian integer |
| 24 | 16 | request UUID bytes; non-nil |
| 40 | 16 | persona UUID bytes; non-nil |
| 56 | 32 | raw root-statement SHA-256 digest |
| 88 | 2 | persona-label byte length |
| 90 | 2 | key-fingerprint byte length |
| 92 | 2 | persona-anchor byte length |
| 94 | 2 | reserved; zero |
| 96 | variable | persona label, fingerprint, then persona anchor |

The persona anchor is exactly 32 bytes in canonical unpadded Base64url (43
display bytes), and issuance is nonnegative. The maximum persona-root prompt is
523 payload bytes or 543 bytes including the header.

All prompt types contain display evidence only. None contains artifact or
statement bytes, a file descriptor, signer path, private/public key, agent
socket, PIN, wallet credential, or database handle.

## Decision

Message types are `2` approve, `3` decline, and `4` cancel. Each has exactly one
16-byte payload: the request UUID from the prompt. A mismatched UUID, nonzero
exit status, missing EOF, extra output, timeout, or malformed message fails
closed. There is no text or extensible reason field.

Approval is not sufficient by itself. After an approve response, the daemon
rechecks the caller connection and active signer policy, invokes the configured
signer on the already sealed, reviewed input, verifies the fresh signature in
the purpose-specific namespace against the registered public key, confirms the
result still matches what was approved, and rechecks signer policy before
returning a proof.

## Process constraints

The production helper is fixed at `/usr/lib/a-quo/a-quo-consent`. The daemon
requires every path component to be root-owned, non-symlink, and not
group/world-writable. It clears the environment and restores only a small
Wayland/runtime/locale allowlist. It passes no session-bus, X11, loader, path,
agent, or user cursor override. The child gets 90 seconds; the parent kills its
process group and reaps it at 95 seconds.

Tests cover exact round trips, unknown versions/types/flags, length smuggling,
invalid UTF-8, unsafe display characters, reserved bytes, oversized declared
payloads, invalid domain/TXT/lifetime combinations, invalid persona anchors or
root times, malformed and
UUID-mismatched responses, child timeout, and all three terminal decisions.
