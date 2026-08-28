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
