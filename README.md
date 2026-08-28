# A Quo

A Quo is a portable identity, signing, and verification layer. It lets a person
sign plugins, prose, images, archives, and other files with a chosen persona,
then lets another person verify exactly what the available evidence proves.

The name of the product is **A Quo**. The repository and command are `a-quo`,
and the Omarchy plugin identifier is `a-quo.identity`.

## Current status

This repository is an early, security-conscious prototype. The first slice
creates portable proof bundles using OpenSSH's SSHSIG format. It works with
ordinary SSH keys and with FIDO-backed SSH keys supported by `ssh-keygen`.

It deliberately does **not** claim that:

- a validly signed plugin is safe;
- a persona is a government-verified legal identity;
- a signer is still trusted or authorized today;
- an artifact was reviewed, reproducibly built, or free from malware.

Those are separate evidence questions and will stay separate in the interface.

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

Generate or select an SSH key. Hardware-backed Ed25519 FIDO keys are preferred
for durable personas where the hardware is available.

```sh
mise exec -- cargo run -p a-quo-cli -- sign article.md \
  --key ~/.ssh/id_ed25519_sk \
  --public-key ~/.ssh/id_ed25519_sk.pub \
  --persona "Example Publisher"

mise exec -- cargo run -p a-quo-cli -- verify article.md \
  --proof article.md.a-quo-proof.json
```

Do not use the prototype as the sole control for high-risk installation or as
a replacement for an official Swiss or EU identity wallet.

## Architecture and direction

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Proof format](docs/PROOF-FORMAT.md)
- [Roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See `LICENSE`.
