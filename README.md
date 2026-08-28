# A Quo

A Quo is a portable identity, signing, and verification layer. It lets a person
sign plugins, prose, images, archives, and other files with a chosen persona,
then lets another person verify exactly what the available evidence proves.

The name of the product is **A Quo**. The repository and command are `a-quo`,
and the Omarchy plugin identifier is `a-quo.identity`.

## Current status

This repository is an early, security-conscious prototype. It creates portable
proof bundles using OpenSSH's SSHSIG format and maintains separate local
publishing personas with public-key rotation and compromise history. It works
with ordinary SSH keys and with FIDO-backed SSH keys supported by `ssh-keygen`.

It deliberately does **not** claim that:

- a validly signed plugin is safe;
- a persona is a government-verified legal identity;
- a signer is still trusted or authorized today;
- an artifact was reviewed, reproducibly built, or free from malware.

Those are separate evidence questions and will stay separate in the interface.

The Omarchy adapter can also inspect signed release archives, install a release
disabled, and update an A Quo-managed installation with publisher-continuity,
downgrade, and rollback checks. See [Signed Omarchy packages](docs/OMARCHY.md).

The Linux consent foundation is also implemented as a strict binary
`SOCK_SEQPACKET` protocol with descriptor passing, same-user peer checks,
bounded sealed artifact snapshots, sealed proof responses, and a private
per-user daemon that composes persona policy with proof creation. A separate
direct-Wayland consent process now uses a second closed pipe protocol and never
receives artifact bytes, signer paths, or key material. The daemon trusts only
the packaged root-owned `/usr/lib/a-quo/a-quo-consent`; a source checkout or
missing package therefore fails closed with `consent_unavailable`. The Linux
CLI implements `request-sign`, rechecks the same open artifact after consent,
verifies the returned proof, and writes it only if it matches the selected
local persona.

Short-lived DNS domain-control proofs are implemented through the same busless
consent boundary but use a separate statement schema, protocol message, and
SSHSIG namespace. A Quo prints the exact TXT commitment to publish. Offline
verification makes no network request; an explicit `--live` lookup reports the
signature, publication match, and DNSSEC state separately. Even a DNSSEC-backed
match establishes current technical publication control only—not legal
ownership, registrant identity, or website safety.

Versioned persona metadata backup is also implemented. It can move a local
persona label, UUID, public keys, lifecycle states, and event history between A
Quo installations. It never exports private keys, signer paths, wallet data, or
cryptographic recovery authority.

Portable persona continuity is implemented as a protocol and CLI prototype. A
random persona-specific root is signed by its initial key, and each routine
rotation requires the old and new keys to sign identical RFC 8785 JSON under a
purpose-specific SSHSIG namespace. Linux can create the root through the
private daemon and a root-specific trusted Wayland consent screen; the client
re-verifies the sealed result before writing it. Verification still requires
an expected root digest supplied separately. Trusted two-key transition consent
and threshold recovery are not yet implemented.

Offline embedded C2PA verification is implemented on Linux through a separate,
no-network Bubblewrap worker. It validates local content bindings for exact
media bytes while reporting certificate trust, CAWG identity, legal identity,
truth, and A Quo persona linkage as separate and currently unestablished
questions. C2PA parsing never enters the signing daemon. See
[Offline C2PA verification](docs/C2PA.md).

## Development

Install [Mise](https://mise.jdx.dev/), then run:

```sh
mise trust
mise install
mise run check
mise run audit
```

No system Rust installation is expected or supported by this repository.

## Prototype usage

Create a persona, then enroll only its public key. The local UUID is not put in
public proof bundles.

```sh
mise exec -- cargo run -p a-quo-cli -- persona create \
  --label "Example Publisher" --purpose project

mise exec -- cargo run -p a-quo-cli -- persona key-add \
  --persona-id PERSONA_ID \
  --public-key ~/.ssh/id_ed25519.pub \
  --provider openssh-file

mise exec -- cargo run -p a-quo-cli -- persona key-bind \
  --fingerprint KEY_FINGERPRINT \
  --signing-key ~/.ssh/id_ed25519
```

`key-bind` stores only the resolved local path. It does not import private key
bytes. SSH-agent personas bind their matching public-key stub; OpenSSH-file and
FIDO personas normally bind a mode-0600 private key or hardware stub. Binding
prepares trusted daemon selection.

Export, inspect, and restore non-secret persona metadata:

```sh
mise exec -- cargo run -p a-quo-cli -- persona backup-export \
  --persona-id PERSONA_ID \
  --output publisher.a-quo-persona-backup.json

mise exec -- cargo run -p a-quo-cli -- persona backup-inspect \
  publisher.a-quo-persona-backup.json

mise exec -- cargo run -p a-quo-cli -- persona backup-import \
  publisher.a-quo-persona-backup.json
```

Export creates a new mode-0600 file on Unix and refuses to overwrite anything.
The backup is unsigned and can correlate the persona's history: internal
validation detects inconsistent edits, not a coherent rewrite by an attacker.
Import refuses persona/key collisions and restores no signer reference; bind an
available signer explicitly afterward.

On Linux, create a persona root with the registered active signer and trusted
local consent:

```sh
mise exec -- cargo run -p a-quo-cli -- continuity root-request \
  --persona-id PERSONA_ID \
  --output publisher.a-quo-persona-root.json
```

The prompt displays the exact anchor and root digest, warns that this is a
long-lived correlating identity, and requires explicit confirmation. The proof
is still self-asserted: distribute and pin its printed digest through a separate
trusted channel before relying on later continuity.

Create and verify portable continuity evidence with the low-level
direct-signing commands when an explicit non-daemon workflow is required:

```sh
mise exec -- cargo run -p a-quo-cli -- continuity root-create \
  --persona "Example Publisher" \
  --key ~/.ssh/publisher_ed25519 \
  --public-key ~/.ssh/publisher_ed25519.pub \
  --output publisher.a-quo-persona-root.json

mise exec -- cargo run -p a-quo-cli -- continuity root-verify \
  publisher.a-quo-persona-root.json

mise exec -- cargo run -p a-quo-cli -- continuity transition-create \
  --root publisher.a-quo-persona-root.json \
  --previous-key ~/.ssh/publisher_ed25519 \
  --previous-public-key ~/.ssh/publisher_ed25519.pub \
  --next-key ~/.ssh/publisher_next_ed25519 \
  --next-public-key ~/.ssh/publisher_next_ed25519.pub \
  --output rotation-1.a-quo-persona-transition.json

mise exec -- cargo run -p a-quo-cli -- continuity chain-verify \
  --root publisher.a-quo-persona-root.json \
  --transition rotation-1.a-quo-persona-transition.json \
  --expected-root-sha256 INDEPENDENTLY_OBTAINED_ROOT_DIGEST
```

For later rotations, repeat `--prior-transition` in sequence order when
creating and `--transition` in sequence order when verifying. `root-create` and
`transition-create` sign key paths directly and do not use A Quo's trusted
consent UI; they must not be silently automated. A digest copied from the same
untrusted proof is not an independent root pin.

On Linux, a packaged install with the private daemon running can request an
interactive signature without passing a signer path to the client:

```sh
mise exec -- cargo run -p a-quo-cli -- request-sign article.md \
  --persona-id PERSONA_ID --kind article
```

The client sends an already-open file descriptor, waits for approval of its
exact digest, then independently verifies the sealed proof before writing it.
The trusted helper must be installed at its root-owned package path; a source
checkout alone deliberately cannot substitute another approval program.

Request a short-lived domain-control proof, publish the exact TXT record shown,
then explicitly request a live DNS observation:

```sh
mise exec -- cargo run -p a-quo-cli -- domain request-proof YOUR_DOMAIN \
  --persona-id PERSONA_ID

mise exec -- cargo run -p a-quo-cli -- domain verify \
  --proof YOUR_DOMAIN.a-quo-domain-proof.json

mise exec -- cargo run -p a-quo-cli -- domain verify \
  --proof YOUR_DOMAIN.a-quo-domain-proof.json --live
```

The first verification is offline and establishes only the valid signed
statement. The second deliberately queries DNS and distinguishes a
DNSSEC-authenticated match, an unsigned observation, and control not
established.

The lower-level portable `sign` command remains available for development and
explicit scripting. It requires both `--key` and `--public-key` and does not use
the trusted consent window. A real OpenSSH `sk-*` security-key public key can be
registered as `fido2`; A Quo rejects that label for ordinary keys.

```sh
mise exec -- cargo run -p a-quo-cli -- sign article.md \
  --key ~/.ssh/id_ed25519_sk \
  --public-key ~/.ssh/id_ed25519_sk.pub \
  --persona-id PERSONA_ID

mise exec -- cargo run -p a-quo-cli -- verify article.md \
  --proof article.md.a-quo-proof.json
```

Inspect a signed Omarchy release before approving installation or update:

```sh
mise exec -- cargo run -p a-quo-cli -- omarchy inspect plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json

mise exec -- cargo run -p a-quo-cli -- omarchy install plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json --yes

mise exec -- cargo run -p a-quo-cli -- omarchy update plugin-v2.tar.zst \
  --proof plugin-v2.tar.zst.a-quo-proof.json --yes
```

`--yes` means the user reviewed that exact package. A valid signature identifies
the package bytes and locally recognized publisher; it does not make plugin code
safe. New installs remain disabled until separately enabled through Omarchy.

Verify an embedded local C2PA manifest without fetching remote or sidecar data:

```sh
mise exec -- cargo run -p a-quo-cli -- media verify photo.jpg
mise exec -- cargo run -p a-quo-cli -- media verify photo.jpg --json
```

Success establishes a valid local content binding only. It does not establish
certificate trust, current revocation status, creator identity, truth,
originality, safety, or a link to an A Quo persona. Missing, unsupported,
remote-only, and unreadable provenance return a report and a nonzero exit.

Do not use the prototype as the sole control for high-risk installation or as
a replacement for an official Swiss or EU identity wallet.

## Architecture and direction

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Proof format](docs/PROOF-FORMAT.md)
- [Personas and key history](docs/PERSONAS.md)
- [Persona continuity, backup, and recovery](docs/KEY-RECOVERY.md)
- [Portable persona continuity format](docs/CONTINUITY.md)
- [Signed Omarchy packages](docs/OMARCHY.md)
- [Consent IPC decision](docs/CONSENT-IPC.md)
- [Private signing daemon](docs/DAEMON.md)
- [DNS domain-control proofs](docs/DOMAIN-CONTROL.md)
- [Offline C2PA verification](docs/C2PA.md)
- [Roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See `LICENSE`.
