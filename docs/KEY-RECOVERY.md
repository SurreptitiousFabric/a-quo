# Persona continuity, backup, and recovery

**Status:** metadata backup implemented; signed continuity and threshold
recovery remain gated on their trusted consent flows

## Three different operations

A Quo must not call every replacement key “recovery.” These operations carry
different evidence:

| Operation | Required authority | What it can establish |
| --- | --- | --- |
| Metadata restore | a user-selected local backup | Recreates non-secret local labels, public keys, statuses, and history; establishes no cryptographic continuity |
| Routine rotation | previous signing key **and** new signing key | Both key holders approved the next signing key for this persona |
| Recovery | threshold of previously authorized offline recovery keys **and** new signing key | The pinned recovery policy authorized replacing an unavailable or compromised signing key |

Possession of an exported file is never authority to sign. A valid recovery
signature does not prove legal identity, and it cannot rescind historical facts
signed by an older key.

## Persona-specific trust anchor

Recovery requires an explicit public continuity identifier. When a user opts
in, A Quo will generate a random 256-bit `persona_anchor` for that persona. It
is never shared across personas and is not derived from a legal identity,
device, wallet, account, or global A Quo identifier.

Publishing an anchor intentionally makes events within that one persona
correlatable. The ordinary artifact proof remains unchanged and does not expose
the local persona UUID or an anchor unless the user separately chooses a
continuity proof.

An initial policy is self-asserted until a verifier pins it through a trusted
out-of-band exchange or observes it through separately verified evidence such
as a DNSSEC domain proof or transparency-log inclusion. A policy created after
a signing-key compromise cannot retroactively prove that the attacker was not
the party who created it.

## Signed recovery policy

The versioned policy statement will contain only public data:

- statement schema and canonicalization identifier;
- persona anchor and self-asserted persona label;
- monotonically increasing policy version;
- digest of the previous policy, except at version 1;
- bounded set of recovery public keys and their fingerprints;
- threshold of distinct recovery keys required;
- issuance and expiry times; and
- no private key, signer path, wallet credential, PIN, or recovery code.

Policy payloads use RFC 8785 JSON Canonicalization Scheme bytes and a distinct
OpenSSH SSHSIG namespace. OpenSSH defines namespaces specifically to prevent a
signature made for one interpretation domain from being accepted in another.
Every listed recovery key must prove possession when the initial policy is
created; merely naming somebody else's public key is insufficient.

Policy version `N+1` must be authorized by the threshold in trusted version `N`
and by the threshold declared in version `N+1`. Versions cannot be skipped or
rolled back. Each fingerprint counts at most once toward a threshold. This
follows the conservative root-update shape used by The Update Framework rather
than treating one mutable database row as a root of trust.

## Signing-key transitions

A routine transition statement binds:

- the persona anchor and exact policy digest;
- the exact previous and next public keys/fingerprints;
- the next transition sequence number;
- a closed reason and bounded time; and
- the digest of the previous transition, when one exists.

It requires distinct valid signatures from both the previous and next signing
keys. The second signature proves custody of the proposed key and prevents a
mistyped or substituted public key from becoming authoritative.

A recovery transition replaces the previous-key signature with the configured
threshold of distinct recovery-key signatures. It still requires the next
signing key to sign. A compromised or retired online signing key cannot approve
a recovery transition by itself.

All policy and transition signatures use separate SSHSIG namespaces from
artifacts, DNS domain control, and each other. Inputs, signature arrays, key
counts, text fields, and validity periods are hard-bounded. Duplicate keys,
duplicate signatures, unknown fields, noncanonical encodings, rollback, gaps,
and mismatched fingerprints fail closed.

## Portable metadata backup

The first implementation slice is a versioned JSON backup for one persona. It
contains the local persona record, OpenSSH public keys, lifecycle states, and
append-oriented event history. It deliberately excludes:

- private keys and hardware-key stubs;
- signer paths and SSH-agent configuration;
- recovery secrets, PINs, and wallet material;
- official Swiss/EU credentials; and
- any claim that the backup is a signed continuity proof.

Exports are bounded, written as new mode-0600 files on Unix, and never overwrite
an existing path. Import validates every public-key fingerprint, provider,
status/time relationship, event reference, field bound, and persona UUID before
one atomic transaction. It refuses collisions and never restores signer paths;
the owner must explicitly bind a currently available signer afterward.

The JSON schema and standard OpenSSH public-key text are portable across A Quo
platform adapters. The file is sensitive because it can correlate a persona's
history even though it contains no signing secret. Users should protect and
delete copies according to their privacy needs.

The backup is deliberately unsigned in this first slice. Validation detects
malformed data, fingerprint substitution, and internally inconsistent history;
it cannot distinguish a coherent rewrite by someone who can replace the whole
file. A backup must therefore be treated as user-supplied metadata, never as a
trust root or portable proof shown to somebody else.

The implemented CLI surface is:

```text
a-quo persona backup-export --persona-id PERSONA_ID --output NEW_FILE
a-quo persona backup-inspect FILE
a-quo persona backup-import FILE
```

Inspection validates without opening a persona store. Import validates before
opening its destination store, then refuses any persona-ID or key-fingerprint
collision and writes all restored records in one database transaction.

## Verification language

Verifiers report these dimensions independently:

- backup parsed and internally consistent;
- policy signatures and threshold valid;
- policy pinned or witnessed before the relevant compromise;
- transition signatures and sequence valid;
- old/new/recovery key lifecycle state in the selected trust source; and
- current artifact signature valid.

No single green “identity recovered” result collapses those facts. If the
policy was not pinned before compromise, A Quo must say so. Historical artifact
proofs remain inspectable after rotation or recovery and are never rewritten.

## Implementation order

1. strict non-secret metadata export/import with no signing authority (implemented);
2. persona anchor and dual-signed routine continuity statements;
3. threshold recovery policy creation and rotation;
4. trusted multi-key consent ceremonies and recovery transitions;
5. optional, separately verified transparency-log and DNS anchoring adapters.

## Standards rationale

- [OpenSSH SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
  supplies detached signatures and explicit interpretation namespaces.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) supplies an interoperable
  canonical JSON representation rather than relying on one language's struct
  field order.
- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/)
  supplies the old-threshold plus new-threshold, exact-next-version model for
  changing high-value root keys.
- [Sigstore's security model](https://docs.sigstore.dev/about/security/)
  explains why append-only public evidence still needs inclusion verification
  and monitoring; a log is an evidence source, not magical recovery authority.
