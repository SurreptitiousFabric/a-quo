# Contributing

Use Mise for the pinned toolchain and project tasks:

```sh
mise trust
mise install
mise run check
mise run audit
```

Changes to proof formats, key handling, trust decisions, plugin installation,
or consent UI must include a threat analysis and negative-path tests. Avoid
adding network calls to the core verifier; offline verification is a design
requirement.

## Maturity claims

The [A Quo maturity policy](docs/MATURITY.md) defines the Project's seven
Status gates and its separate Acceptance-evidence field. Status applies to the
outcome stated by an issue, not to a related component or the amount of effort
already spent.

Every issue or pull request proposing a status change must link:

- the exact public revision or immutable external artifact;
- success, tamper, hostile-input, and failure-path evidence, with a concrete
  reason for anything inapplicable;
- applicable cryptography, trusted-consent, packaging, accessibility, or
  external-integration evidence;
- documentation, threat-model changes, residual limitations, and non-claims;
  and
- every gate that remains before the issue can advance again.

Move a card backward when a regression, invalidated assumption, changed
dependency, or stale review means its current evidence no longer meets the
gate. Do not use Priority or Dependency as a substitute for maturity.

Use the repository's work-item issue form and pull-request template so these
claims stay reviewable. Sensitive vulnerabilities belong in a private security
advisory, never in public acceptance evidence.
