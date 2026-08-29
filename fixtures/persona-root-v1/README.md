# Persona-root v1 interoperability vector

This directory contains public, fictional test evidence for the portable
persona-root distribution format. `root-proof.json` was signed by a disposable
Ed25519 key created only for this vector. No private key or recovery material is
retained.

The fictional persona is `JuniperQuill`. Its stable root-statement SHA-256 is:

```text
1f70a193000df6914879989921714e75c0f409247824ed721c14e18f9ce87b75
```

The files are:

- `root-proof.json`: the existing signed persona-root proof;
- `root-card.json`: exact canonical RFC 8785 public card bytes;
- `pin-uri.txt`: the complete digest-only QR/text value;
- `root-pin-tofu.json`: simulated TOFU provenance;
- `root-pin-same-channel.json`: simulated same-channel provenance;
- `root-pin-out-of-band.json`: simulated user-confirmed separate-route
  provenance; and
- `vector.json`: expected file/rendering digests and evidence dimensions.

The provenance records demonstrate formats and result language. They are not
evidence that real independent channels, people, devices, or trusted times were
used.

## Verification without A Quo

An independent implementation must follow the complete algorithm in
[`docs/ROOT-DISTRIBUTION.md`](../../docs/ROOT-DISTRIBUTION.md), including closed
schemas, canonicalization, key-fingerprint binding, algorithm restrictions,
and exact card/pin comparison.

OpenSSH can check the SSHSIG component after extracting the proof's public
fields. For example, with `jq`, GNU `basenc`, and OpenSSH available:

```sh
jq -r '.payload' root-proof.json | basenc --base64url -d > root-statement.json
jq -r '.signature.value' root-proof.json > root-signature.sshsig
jq -r '.signature.public_key' root-proof.json > root-public-key.pub
printf 'a-quo-persona-root %s\n' "$(cat root-public-key.pub)" > root.allowed_signers
ssh-keygen -Y verify -f root.allowed_signers -I a-quo-persona-root \
  -n a-quo-persona-root-v1 -s root-signature.sshsig < root-statement.json
sha256sum root-statement.json
```

The final SHA-256 must equal the complete digest above. On systems without GNU
`sha256sum`, use an equivalent raw-file SHA-256 tool. A successful generic
SSHSIG command alone does not validate A Quo's schemas, canonical bytes,
fingerprint binding, card, pin provenance, or nonclaims.

Automated tests verify the proof, every canonical file, every expected digest,
the accessible renderings, and all separated comparison dimensions. The vector
does not establish legal identity, trusted time, current authority, current
history freshness, truth, or safety.
