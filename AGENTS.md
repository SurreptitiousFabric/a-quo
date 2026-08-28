# Working on A Quo

## Toolchains

Use Mise for every coding-language toolchain. Run Rust commands through
`mise exec -- ...` or the named `mise run ...` tasks. Do not install language
runtimes from the operating-system package manager.

## Security rules

- Never log, commit, copy, or silently back up private keys, PINs, recovery
  material, wallet credentials, or complete sensitive credential payloads.
- Keep signing consent outside the Omarchy bar plugin process.
- Do not put signing or consent authority on D-Bus. Linux callers use the
  closed, versioned private Unix-socket protocol described in
  `docs/CONSENT-IPC.md`; optional buses may provide discovery only.
- A valid signature is evidence about bytes and a key. It is never, by itself,
  evidence that software is safe or that a signer has a legal identity.
- Preserve separation between personas; do not introduce a universal identity
  or correlation identifier.
- Treat proof parsing and archive inspection as hostile-input boundaries.
- Add tests for tampering and failure paths whenever a proof format changes.

## Required checks

Run `mise run check` before committing Rust changes.
