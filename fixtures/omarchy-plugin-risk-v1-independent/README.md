# Independent Omarchy risk-record oracle

This corpus provides a byte-level oracle outside A Quo's Rust constructors,
canonicalizer, and digest helpers. It checks whether A Quo accepts reviewed
canonical records, enforces their joined bindings, and rejects selected hostile
mutations.

## Provenance and boundary

The existing `fixtures/omarchy-plugin-risk-v1` corpus was used only as a
schema-field checklist. The subject, publisher, provider, persona, operation,
report, file, and digest values in this directory were reauthored and rebound
without calling A Quo's Rust record constructors, canonicalization functions,
or digest functions.

The expected bytes were frozen with `jq 1.8.2` using:

```sh
LC_ALL=C jq -j -S -c . FILE
```

The expected hashes were frozen with GNU coreutils `sha256sum 9.11` using:

```sh
sha256sum FILE
```

This is deliberately a restricted JSON subset: ASCII strings, booleans,
`null`, and nonnegative integers within the interoperable safe-integer range.
There are no floating-point numbers. The corpus does not claim that `jq`
implements RFC 8785 for arbitrary JSON.

`oracle-manifest.json` records the exact file inventory, sizes, hashes,
construction tools, expected operation and decision, and nonclaims. The
standalone verifier checks those facts and all joined digest bindings without
executing A Quo. The Rust integration test then supplies the same raw bytes to
only A Quo's public parsers and joined validator.

The provider-registry and native-report object bytes are not members of the v1
risk-record format and remain opaque external inputs. This corpus binds their
recorded digests consistently across the scoped records; it does not claim to
verify those external objects or their semantics.

## Test classification

| Coverage | Classification |
| --- | --- |
| Exact bytes, sizes, hashes, digest bindings, decision derivation | Independent oracle |
| Public parser acceptance and joined validation | A Quo black-box contract |
| Duplicate keys, noncanonical bytes, reordered reasons/bindings, substitution, invalid decision | Hostile mutation against public API |
| `risk_contract.rs` constructed records and generated goldens | Internal round-trip regression |

This fixture does not establish artifact safety, policy correctness outside the
recorded rule, legal identity, native-report semantics, or production
readiness.
