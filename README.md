# A Quo

**A Quo records narrowly scoped evidence about which key signed exact digital
bytes, how a self-created persona changed keys, and what a supported external
presentation establishes. It does not turn those facts into a universal trust
decision.**

> **Signed does not mean safe.** A valid signature is evidence about bytes and
> a key. By itself it does not establish that the bytes are harmless, true,
> original, reviewed, current, or connected to a legal identity.

A Quo can create separate personas for personal publishing, pseudonymous work,
a project, or an organization; sign and verify files; preserve signed
continuity as routine keys change; and retain bounded public recovery evidence.
The `legal-bridge` persona purpose labels a planned legal-wallet presentation
bridge; wallet integration is not implemented. Signed Omarchy plugins are the
first concrete integration, not the whole product.

This repository is an early security-conscious prototype. The portable proof
formats and some renderers work across Linux, macOS, and Windows. Trusted
signing consent, archive inspection, Omarchy lifecycle operations, and isolated
media or supply-chain verification currently have Linux-specific boundaries.
Packaging and release qualification are unfinished.

The product is **A Quo**. The repository and command are `a-quo`; the Omarchy
plugin identifier is `a-quo.identity`.

## Product model

- A **persona** is one deliberately separate public role. A Quo does not create
  a universal identity or correlation identifier across personas.
- An **artifact** is the exact file or byte sequence being discussed.
- A **proof bundle** is a portable signed statement plus the public material
  required to verify it.
- **Continuity** is ordered signed evidence that one routine key followed
  another under one persona root.
- A **credential presentation** is a narrowly requested response from an
  external wallet. Wallet integration is planned; A Quo does not import or own
  wallet credentials or private keys.

Private keys remain with their configured OpenSSH provider, agent, or security
key. A Quo stores public material and an explicitly configured signer reference,
not private-key contents, PINs, recovery secrets, or wallet credentials.

## Central journey

The intended end-to-end journey is deliberately explicit:

1. Create one persona and bind one supported signer without importing its
   private key.
2. On Linux, ask the private per-user daemon to snapshot an artifact and obtain
   approval from the separate direct-Wayland consent process.
3. Publish the artifact with its portable proof bundle.
4. Verify the exact bytes and report key, continuity, policy, freshness,
   provenance, review, and safety evidence as separate facts.
5. When the routine key changes, authorize an exact transition under the
   separately pinned persona root. Recovery additionally uses a separately
   configured threshold policy and explicit successor-key custody.
6. For Omarchy, inspect the exact signed package and its structural or optional
   behavioural evidence before a separately acknowledged install, update, or
   uninstall operation.

Only bounded pieces of that journey are implemented. In particular, the
joined installed-package/consent/Omarchy evaluator remains a guarded contract;
its armed clean-system path has not run. Current maturity and the next unmet
gate for every work item are recorded in the
[maturity audit](docs/MATURITY-AUDIT.md), not inferred from this overview.

## Current support boundary

| Area | Current bounded capability | Important open boundary |
| --- | --- | --- |
| Artifact proofs | Portable SSHSIG bundle creation, inspection, and offline exact-byte verification | Direct `sign` has no trusted consent; a signature is not safety or legal identity |
| Personas | Separate local personas, supported signer bindings, rotation, compromise history, and terminal revocation | The local store is not an independently witnessed ledger |
| Continuity and backup | Root and transition verification; bounded evidence-only backup import/comparison; explicit direct, recovery, and terminal materialization modes | External pins may be stale or same-channel; multi-candidate and existing-live fork resolution remain open |
| Threshold recovery | Versioned M-of-N public recovery policy, mixed-chain verification, atomic live commit, and one bounded participant-consent ceremony | No secret sharing; complete multi-party product ceremony, independent-holder hardware evidence, UX, and external review remain open |
| Trusted Linux signing | Private versioned Unix socket, descriptor-passed immutable snapshot, and separate direct-Wayland approval helper | No D-Bus approval authority, secure-attention guarantee, or completed accessibility path |
| Omarchy lifecycle | Hostile package inspection plus bounded install, update, rollback, uninstall, and retained-recovery logic | Same-UID pathname races, crash durability, safe purge, race-free exposure, behavioural review, and clean-system evidence remain gates |
| Exact Omarchy inputs | Closed AArch64 locks for OCI, builder context, ALARM rootfs, QEMU, AAVMF, and the joined lifecycle; offline sealed-snapshot verification | Exact selection supplies no external authentication, durable retention, build authority, provenance, safety, VM evidence, or runnable target |
| DNS control | Short-lived exact-name statements, offline verification, and optional live DNSSEC lookup | At most current technical publication control of the exact name |
| C2PA | Local embedded-manifest verification in an isolated no-network Linux worker | Certificate trust, creator identity, and CAWG identity assertions remain separate |
| Sigstore/SLSA | Offline bundle cryptography and authenticated claims under explicit policy | Build-policy acceptance, reproducibility, freshness, and artifact safety remain separate |
| External wallets | Design target for narrowly scoped swiyu and EU Digital Identity Wallet presentations | Not implemented; issuer, validity, revocation, disclosure, and wallet policy stay external |
| Packaging | Passive non-publishing scaffold, target profiles, and non-mutating evaluator contracts | Not an installable supported release; clean-system, provenance, signing, accessibility, and external review remain open |

The [threat model](docs/THREAT-MODEL.md) is authoritative for system-wide
adversaries and residual risks. The [maturity policy](docs/MATURITY.md) defines
what the status terms mean.

## What verification says

A Quo treats trust as a vector, not a badge:

| Evidence | A successful check can establish | It does not establish by itself |
| --- | --- | --- |
| Artifact signature | The bundled key signed the exact verified bytes for the stated purpose | Truth, originality, safety, review, current authorization, or legal identity |
| Persona continuity | The supplied transitions form a valid chain from a separately pinned root; an optional exact head pin selects one known tip | Freshness or independence of the pin, absence of a withheld sibling/newer history, or future signer availability |
| Recovery transition | The configured threshold of distinct recovery-only keys and the proposed successor key authorized the exact transition | Guardian identity, independence, absence of collusion, or reconstruction of a lost private key |
| DNS statement | A fresh exact-name commitment and the reported DNSSEC state | Legal ownership, historic control, or control of every service under the name |
| Omarchy package | Exact package bytes, manifest structure, publisher-key evidence, and the operation-specific receipt facts | Behavioural safety, malware absence, trusted installation consent, runtime enablement, or source provenance |
| C2PA manifest | Local content binding and the assertions the isolated verifier actually validated | General certificate trust, creator identity, or truth of depicted content |
| Sigstore/SLSA bundle | Bundle cryptography and the exact authenticated claims under caller-supplied roots and policy | Acceptable build policy, reproducibility, source safety, or TUF-style freshness |
| Credential presentation | In a future adapter, only the requested disclosed claim under the named issuer and policy | A universal “verified person” identity or unrelated attributes |

Reports retain unknown and unestablished facts instead of converting missing
evidence into a positive result.

## Quick start from source

Install [Mise](https://mise.jdx.dev/), then use the repository-pinned toolchain:

```sh
mise trust
mise install
mise run check
mise run audit
```

No system Rust installation is expected or supported by this repository.

### Create a persona and bind a signer

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

`key-bind` stores the resolved local path, not private-key bytes. Agent and
OpenSSH security-key providers use the matching public-key stub. See
[Personas](docs/PERSONAS.md) for provider and correlation boundaries.

### Sign and verify exact bytes

The direct command is useful for development and explicit scripts, but bypasses
the trusted consent screen:

```sh
mise exec -- cargo run -p a-quo-cli -- sign article.md \
  --key ~/.ssh/id_ed25519 \
  --public-key ~/.ssh/id_ed25519.pub \
  --persona-id PERSONA_ID

mise exec -- cargo run -p a-quo-cli -- verify article.md \
  --proof article.md.a-quo-proof.json
```

With the packaged Linux daemon and fixed root-owned helper installed, request
interactive exact-artifact signing without giving the client a signer path:

```sh
mise exec -- cargo run -p a-quo-cli -- request-sign article.md \
  --persona-id PERSONA_ID --kind article
```

The closed transport and consent boundary are specified in
[CONSENT-IPC.md](docs/CONSENT-IPC.md), [DAEMON.md](docs/DAEMON.md), and
[APPROVAL-PROTOCOL.md](docs/APPROVAL-PROTOCOL.md).

### Establish and verify continuity

```sh
mise exec -- cargo run -p a-quo-cli -- continuity root-request \
  --persona-id PERSONA_ID \
  --output publisher.a-quo-persona-root.json

mise exec -- cargo run -p a-quo-cli -- continuity transition-request \
  --persona-id PERSONA_ID \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --next-key ~/.ssh/id_ed25519_next \
  --next-public-key ~/.ssh/id_ed25519_next.pub \
  --next-provider openssh-file \
  --output publisher.rotation-1.json

mise exec -- cargo run -p a-quo-cli -- continuity chain-verify \
  --root publisher.a-quo-persona-root.json \
  --transition publisher.rotation-1.json \
  --expected-root-sha256 INDEPENDENT_ROOT_DIGEST \
  --expected-head-sequence 1 \
  --expected-head-sha256 INDEPENDENT_ROTATION_STATEMENT_DIGEST
```

Root cards and verifier-owned pin records are public evidence, never signing or
recovery authority. Obtain root, head, and recovery-policy pins through the
route whose independence you are willing to claim. See
[ROOT-DISTRIBUTION.md](docs/ROOT-DISTRIBUTION.md),
[CONTINUITY.md](docs/CONTINUITY.md), and
[KEY-RECOVERY.md](docs/KEY-RECOVERY.md) for backup comparison, direct/recovery
activation, terminal hydration, threshold policy, and ceremony commands.

### Create and verify DNS control evidence

```sh
mise exec -- cargo run -p a-quo-cli -- domain request-proof YOUR_DOMAIN \
  --persona-id PERSONA_ID

mise exec -- cargo run -p a-quo-cli -- domain verify \
  --proof YOUR_DOMAIN.a-quo-domain-proof.json

mise exec -- cargo run -p a-quo-cli -- domain verify \
  --proof YOUR_DOMAIN.a-quo-domain-proof.json --live
```

Live verification performs network access. Exact claim and expiry semantics are
in [DOMAIN-CONTROL.md](docs/DOMAIN-CONTROL.md).

### Inspect and manage an Omarchy package

```sh
mise exec -- cargo run -p a-quo-cli -- omarchy inspect plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json

mise exec -- cargo run -p a-quo-cli -- omarchy observe-reference PLUGIN_ID \
  --json

mise exec -- cargo run -p a-quo-cli -- omarchy install plugin.tar.zst \
  --proof plugin.tar.zst.a-quo-proof.json --yes \
  --accept-behavioral-analysis-not-run

mise exec -- cargo run -p a-quo-cli -- omarchy update plugin-v2.tar.zst \
  --proof plugin-v2.tar.zst.a-quo-proof.json --yes \
  --accept-behavioral-analysis-not-run

mise exec -- cargo run -p a-quo-cli -- omarchy uninstall PLUGIN_ID --yes
```

`--yes` acknowledges the lifecycle operation; it is not trusted consent or a
safety override. The separate flag acknowledges that no behavioural reviewer
ran. The exact inspection, reference-observation, staging, exposure, rollback,
and retained-recovery semantics are in [OMARCHY.md](docs/OMARCHY.md). Optional
scanner evidence is governed by [PLUGIN-RISK.md](docs/PLUGIN-RISK.md).

### Verify media or supply-chain evidence

```sh
mise exec -- cargo run -p a-quo-cli -- media verify photo.jpg

mise exec -- cargo run -p a-quo-cli -- supply-chain verify-bundle plugin.tar.zst \
  --bundle plugin.tar.zst.sigstore.json \
  --trusted-root trusted_root.json \
  --identity 'EXPECTED CERTIFICATE IDENTITY' \
  --issuer 'EXPECTED OIDC ISSUER'
```

See [C2PA.md](docs/C2PA.md) and [SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) before
treating those results as policy evidence.

## Packaging and exact-input work

The repository includes non-publishing release scaffolds, passive package
construction, synthetic lifecycle checks, guarded installed evaluators, and
closed exact-input verifiers. Their authoritative commands, target profiles,
preconditions, destructive boundaries, and current nonclaims live in
[PACKAGING.md](docs/PACKAGING.md).

The common non-mutating entry points are:

```sh
mise run release-scaffold-lint
mise run arch-package-target-contract
mise run installed-omarchy-core-lifecycle-contract
mise run installed-a-quo-consent-lifecycle-contract
mise run installed-a-quo-package-lifecycle-contract
mise run omarchy-ubuntu-oci-input-lock-contract
mise run omarchy-builder-context-input-lock-contract
mise run omarchy-alarm-rootfs-input-lock-contract
mise run omarchy-qemu-input-lock-contract
mise run omarchy-aavmf-input-lock-contract
mise run omarchy-joined-input-lock-contract
```

The armed installed evaluators and package lifecycle are destructive,
acknowledged, one-shot operations for specially marked disposable targets. Do
not run them on a development machine. No armed joined path has supplied
clean-system evidence. Historical commits, workflow runs, artifacts, and
digests are retained in [EVIDENCE.md](docs/EVIDENCE.md), not repeated here.

## Security architecture in brief

- Signing and consent authority stay outside the Omarchy bar process and off
  D-Bus. Optional buses may provide discovery or read-only accessibility data
  only.
- Descriptor passing and bounded immutable snapshots bind approval and
  verification to exact bytes.
- Proof parsing and archive inspection are hostile-input boundaries; work is
  bounded and no package or maintainer script is executed during inspection.
- Isolated C2PA and Sigstore verification has no network access; live DNS is an
  explicit exception.
- Persona roots are independent. Reusing labels or keys can still correlate
  activity.
- Same-UID malware, a hostile desktop session, stale external pins, compromised
  build inputs, and unreviewed software remain meaningful threats.

The complete boundary is in [THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Documentation

The [documentation authority map](docs/DOCUMENTATION.md) defines the single
normative home for each subject and keeps dated evidence separate.

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Proof format](docs/PROOF-FORMAT.md)
- [Personas and key history](docs/PERSONAS.md)
- [Portable continuity](docs/CONTINUITY.md)
- [Backup and recovery](docs/KEY-RECOVERY.md)
- [Persona-root distribution](docs/ROOT-DISTRIBUTION.md)
- [Private signing daemon](docs/DAEMON.md)
- [Approval protocol](docs/APPROVAL-PROTOCOL.md)
- [Consent IPC](docs/CONSENT-IPC.md)
- [Signed Omarchy packages](docs/OMARCHY.md)
- [Packaging and support contract](docs/PACKAGING.md)
- [Plugin-risk evidence](docs/PLUGIN-RISK.md)
- [Pinned Omarchy corpus](docs/OMARCHY-CORPUS.md)
- [Accessibility](docs/ACCESSIBILITY.md)
- [DNS domain control](docs/DOMAIN-CONTROL.md)
- [C2PA](docs/C2PA.md)
- [Sigstore and SLSA](docs/SUPPLY-CHAIN.md)
- [Maturity policy](docs/MATURITY.md)
- [Maturity audit](docs/MATURITY-AUDIT.md)
- [Roadmap](docs/ROADMAP.md)
- [Public evidence index](docs/EVIDENCE.md)
- [Repository governance](docs/REPOSITORY-GOVERNANCE.md)
- [Security reporting](SECURITY.md)

Work is tracked on the
[Witness Me! Project](https://github.com/users/SurreptitiousFabric/projects/9).

## License

Apache-2.0. See [LICENSE](LICENSE).
