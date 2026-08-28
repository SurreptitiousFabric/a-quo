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
```

Generate or select an SSH key. A real OpenSSH `sk-*` security-key public key can
be registered as `fido2`; A Quo rejects that label for ordinary keys.

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

Do not use the prototype as the sole control for high-risk installation or as
a replacement for an official Swiss or EU identity wallet.

## Architecture and direction

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Proof format](docs/PROOF-FORMAT.md)
- [Personas and key history](docs/PERSONAS.md)
- [Signed Omarchy packages](docs/OMARCHY.md)
- [Roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See `LICENSE`.
