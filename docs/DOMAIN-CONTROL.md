# DNS domain-control proof v1

**Status:** portable proof and bounded live-verification adapter implemented;
trusted consent and CLI integration pending

## Claim and non-claims

An A Quo domain-control proof combines two independent facts:

1. an A Quo key signed one exact, domain-separated statement; and
2. the exact claimed DNS name currently publishes a commitment to those
   signed statement bytes.

With a DNSSEC-authenticated publication, that can establish current technical
control over publication at one DNS name. It does not establish legal
ownership, registrant identity, control of parent or child names, control of
every website served at that name, historical control, or safety of any
content. An unsigned matching answer is only an observation.

The v1 publication method is DNS TXT at the exact claimed domain. It does not
mint an unregistered underscored DNS node or well-known HTTP URI. Public uses
of those namespaces require registration under
[RFC 8552](https://www.rfc-editor.org/rfc/rfc8552) and
[RFC 8615](https://www.rfc-editor.org/rfc/rfc8615), respectively.

## Signed statement

The proof uses the existing `urn:a-quo:proof:sshsig:v1` envelope and the
distinct SSHSIG namespace `a-quo-domain-control-v1`. Its decoded payload is:

```json
{
  "schema": "urn:a-quo:statement:domain-control:v1",
  "domain": "example.com",
  "nonce": "<unpadded base64url for 32 random bytes>",
  "issued_at": 1787875200,
  "expires_at": 1788480000,
  "signer": {
    "persona": "Example Publisher",
    "key_fingerprint": "SHA256:..."
  }
}
```

`example.com` is used only as RFC-designated documentation text here. The
implementation rejects documentation and other special-use domains so this
example cannot accidentally become a live claim.

The domain is the lowercase ASCII A-label form used for DNS comparison.
Unicode input is converted using strict IDNA processing and must round-trip to
a valid DNS name. IP literals, wildcards, single-label names, special-use test
names, empty labels, ports, paths, user information, and surrounding whitespace
are rejected. The claim covers exactly this name and no inferred registrable
domain, wildcard, parent, or subdomain.

The nonce has 256 bits from the operating system random source. This exceeds
the 128-bit challenge minimum used by ACME in
[RFC 8555](https://www.rfc-editor.org/rfc/rfc8555). A statement must expire
after it is issued and may span at most 30 days. Verifiers allow at most five
minutes of clock skew around the validity boundaries.

## DNS publication

Let `payload` be the exact decoded bytes covered by the SSHSIG. Compute:

```text
commitment = SHA-256("a-quo-domain-dns-txt-v1\0" || payload)
txt-value  = "a-quo-domain-v1=" || BASE64URL-NOPAD(commitment)
```

Publish `txt-value` as one TXT record at the exact statement domain. For the
example above, the instruction is conceptually:

```text
example.com.  TXT  "a-quo-domain-v1=..."
```

The value is short enough for one DNS TXT character-string. A verifier matches
the concatenated character-strings of one TXT record exactly; it does not
perform substring, whitespace, case, or split-record matching. It ignores
unrelated TXT records.

The returned TXT record owner name must equal the claimed domain. A TXT answer
reached by following a CNAME is not accepted, because control of a hosting
target is not necessarily authority to bind the source domain to an identity.

## Verification result

Cryptographic verification checks the envelope schema, domain-specific SSHSIG
namespace, exact signed payload bytes, statement schema, canonical domain,
nonce, validity bounds, bundled public key, stated fingerprint, and signature.
It then derives the one expected TXT value.

Live DNS verification reports these dimensions separately:

- `signature`: whether the domain statement signature is valid;
- `validity`: whether the statement is currently within its bounded lifetime;
- `publication`: whether an exact-owner TXT record matches the commitment;
- `dnssec`: `secure`, `insecure`, `bogus`, or `indeterminate`; and
- `domain_control`: `verified_dnssec`, `observed_unsigned`, or
  `not_established`.

Only a matching record with a DNSSEC chain to a configured trust anchor earns
`verified_dnssec`. A matching record in a provably unsigned zone is reported as
`observed_unsigned`, not cryptographically authenticated domain control. Bogus
or indeterminate DNSSEC never establishes control. This follows the four DNSSEC
states and limitations described by
[RFC 4033](https://www.rfc-editor.org/rfc/rfc4033).

A secure authenticated denial can therefore report `publication: missing` and
`dnssec: secure` while still reporting `domain_control: not_established`.
Absence and mismatch produce negative evidence reports. A timeout, resolver
failure, or malformed over-limit response produces a distinct inability to
obtain evidence, never a false `missing` result. Expiry fails the portable
current-validity check. None of those outcomes rewrites the historical fact
that the key signed the statement.

Removing the TXT record stops future live verification; without a trusted
timestamp or witnessed observation, an old proof cannot establish that the
record existed in the past.

## Operational bounds

- one fully qualified TXT query, so resolver search suffixes cannot alter it;
- three-second requests, two attempts, and a 12-second overall deadline;
- at most 64 answer records, 4 KiB per TXT record, and 64 KiB of total TXT
  material processed;
- DNSSEC validation enabled explicitly with Hickory's default trust anchors;
- exact-owner matching even if the resolver follows a CNAME;
- no D-Bus or desktop portal dependency;
- no automatic DNS updates or registrar credentials; and
- no A Quo logging of resolver configuration or unrelated TXT contents.

The adapter uses the operating system's configured recursive DNS server over
ordinary DNS transport with TCP fallback. DNSSEC authenticates data; it does
not encrypt the query. The configured resolver and network can observe the
queried public domain, and an unsigned result remains vulnerable to network or
resolver substitution—which is why it never earns `verified_dnssec`.

Domain publication is an explicit manual or provider-mediated act. A Quo may
print the exact record to publish, but it does not request DNS credentials or
modify a zone in v1.
