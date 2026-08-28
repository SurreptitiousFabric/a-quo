# SSHSIG proof bundle v1

The first A Quo format is a JSON envelope around a signed, embedded statement.
It is intentionally narrow and versioned by URNs.

## Envelope

```json
{
  "schema": "urn:a-quo:proof:sshsig:v1",
  "payload": "<base64url-encoded statement bytes>",
  "signature": {
    "format": "sshsig",
    "namespace": "a-quo-artifact-v1",
    "value": "-----BEGIN SSH SIGNATURE-----..."
  },
  "verification_material": {
    "format": "openssh-public-key",
    "public_key": "ssh-ed25519 AAAA..."
  }
}
```

The verifier signs and verifies the exact decoded `payload` bytes. It does not
re-serialize JSON before signature verification.

## Statement

```json
{
  "schema": "urn:a-quo:statement:artifact:v1",
  "artifact": {
    "digest": { "algorithm": "sha256", "value": "<lowercase hex>" },
    "size": 123
  },
  "signer": {
    "persona": "Example Publisher",
    "key_fingerprint": "SHA256:..."
  }
}
```

Paths and filenames are excluded because they leak local information and do not
identify content. A later optional claim can bind a distribution filename.

## Meaning

A successful v1 verification establishes only that:

- the supplied artifact has the signed SHA-256 digest and byte length;
- the SSHSIG is valid under the bundled public key and A Quo namespace;
- the bundled public key has the fingerprint named in the signed statement;
- the holder of that key signed the self-asserted persona label.

It does not establish legal identity, current authorization, safety, review,
provenance, freshness, or non-revocation.

## Parsing rules

Implementations must reject unsupported schema identifiers, signature formats,
namespaces, digest algorithms, malformed public keys, fingerprint mismatches,
invalid signatures, and artifact mismatches. Unknown fields may be retained by
forward-compatible envelopes, but no unknown field is security-critical in v1.
