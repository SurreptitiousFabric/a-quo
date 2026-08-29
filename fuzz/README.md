# Coverage-guided parser fuzzing

This independent Cargo workspace exercises A Quo's shipped hostile-byte
boundaries. It never signs material, launches `ssh-keygen`, or treats a
structurally valid proof as a valid signature.

The targets are:

- `continuity_recovery_bytes`: persona-root statements and proofs, routine
  transition statements and proofs, recovery-policy proofs,
  recovery-transition proofs, and the routine/recovery transition union;
- `persona_backup_bytes`: portable persona metadata parsing plus complete key
  lifecycle replay validation.

Successful inputs must survive typed serialization and a second pass through
the same production parser. Canonical signed statement bytes must remain exact.
Rejected inputs must produce bounded printable-ASCII diagnostics. A panic,
sanitizer finding, timeout, memory-limit failure, or failed invariant is a fuzz
failure.

The canonical bounded task enables AddressSanitizer and LeakSanitizer. The
hosted Ubuntu job runs that task. A separately named local fallback disables
only LeakSanitizer for managed environments where running under `ptrace` makes
LSan itself abort; that fallback is not leak-checking evidence.

## Bounds

- outer continuity and recovery proof: 1 MiB;
- canonical signed statement payload: 64 KiB;
- portable persona backup: 4 MiB;
- portable backup keys: 256;
- portable backup events: 4,096;
- recovery authorities in one set: 32.

The bounded smoke campaign uses a smaller 256 KiB generated-input limit for
speed. Deterministic tests exercise rejection immediately beyond the hard byte
and count limits, while longer campaigns can raise `-max_len` to the production
bounds.

## Run

Use the pinned Mise tasks from the repository root:

```console
mise run fuzz-build
mise run fuzz-smoke
```

Each smoke run starts with a fresh ignored output corpus plus the tracked
synthetic seeds. It records the Git revision, clean/dirty state, exact commands,
tool versions, final statistics, and artifact count under `fuzz/logs/`; its
fresh learned corpus is retained under `fuzz/runs/`. Each target has both a
25,000-execution ceiling and a 120-second wall-time ceiling.

On a local runner that fails specifically because LSan cannot operate under
`ptrace`, use the explicitly weaker fallback:

```console
mise run fuzz-smoke-no-lsan
```

Persistent development corpora are separate from reproducible smoke evidence:

```console
mise run fuzz-learn-continuity
mise run fuzz-learn-backup
```

Tracked inputs under `seeds/` contain only synthetic public keys and public
proof-shaped data. Learning tasks write to ignored `corpus/` directories;
reproducible runs use ignored `runs/`; failures go under ignored `artifacts/`.
Never seed a target with private keys, recovery material, wallet credentials,
or sensitive real-world evidence.

The persona-backup seeds cover both backup schemas, schema v2's required
unmanaged/evidence-archive choice, and the archive's tagged routine and
recovery proof shapes. Their synthetic proof material exercises structural
parsing only; it is not evidence that any signature verifies.

The smoke campaign is bounded evidence for one exact revision. It is not an
external security review and does not replace sustained fuzzing.
