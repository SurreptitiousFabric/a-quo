# Signed Omarchy packages

## Purpose

A Quo adds publisher and artifact evidence to Omarchy's plugin workflow. It can
answer “are these exactly the bytes signed by the locally recognized publisher
I expect?” It cannot answer “is this plugin safe?”

The adapter takes local files and does not fetch moving branches or releases.
Publishers may sign the package with the ordinary `a-quo sign` command. Users
must inspect that exact package before explicitly approving install or update.

## Release package contract

A release is a Zstandard-compressed tar archive named conventionally
`*.tar.zst`. Its files are at the archive root, including `manifest.json`; there
is no wrapper directory. In addition to Omarchy schema version 1, A Quo requires
the manifest `version` to be valid semantic versioning.

The hostile-input parser allows only regular files and directories. It rejects:

- absolute, parent, current-directory, non-UTF-8, duplicate, and non-normalized
  paths;
- control and bidirectional formatting characters in paths and displayed
  manifest values;
- symbolic and hard links, devices, FIFOs, and other special entries;
- `.git` content and the reserved `.a-quo-install.json` management receipt;
- entry points that are absent or are not regular archive files; and
- non-zero data following the logical tar end.

Limits are 128 MiB compressed, 600 MiB decompressed stream, 512 MiB total file
content, 128 MiB per file, 4,096 entries, and 64 KiB for `manifest.json`.
Extraction writes each file itself with normalized permissions; it never calls
tar's general-purpose unpack operation.

## Inspection

```sh
a-quo omarchy inspect RELEASE.tar.zst \
  --proof RELEASE.tar.zst.a-quo-proof.json
```

Inspection verifies the proof against the exact archive bytes and parses the
archive without extracting it. If the persona store exists, the report states
whether the signing key is unrecognized, active, retired, or compromised and
whether its signed label agrees with the local persona label. JSON is available
with `--json`.

The report keeps these separate:

- artifact integrity and signature validity;
- local publisher recognition and key state;
- manifest and archive structure;
- the list of executable archive files;
- official Omarchy validation, which has not run yet; and
- runtime safety, which remains `not_evaluated`.

Inspection never executes package content.

## First installation

```sh
a-quo omarchy install RELEASE.tar.zst \
  --proof RELEASE.tar.zst.a-quo-proof.json --yes
```

Installation requires an existing persona store, an active recognized signing
key, and agreement between the signed and local persona labels. A Quo copies
the package once into a mode-0700 staging directory under the Omarchy plugins
filesystem, then verifies, inspects, extracts, and validates that staged copy.

Before an atomic no-replace move, it checks twice that the plugin ID does not
already exist and that stale Omarchy configuration cannot enable that new ID.
It writes `.a-quo-install.json` as local management metadata. A release package
cannot provide or overwrite this file.

The plugin lands disabled. A shell rescan failure is reported, but the disabled
files remain installed so the user can diagnose or remove them. A Quo never
calls Omarchy's enable command; enablement is a separate review decision.

## Update

```sh
a-quo omarchy update NEWER.tar.zst \
  --proof NEWER.tar.zst.a-quo-proof.json --yes
```

Update is limited to an existing A Quo-managed, non-Git plugin with a valid
receipt. The candidate must:

- have the same plugin ID;
- be signed by an active key belonging to the same local persona that installed
  the prior release (normal key rotation within that persona is allowed); and
- have strictly greater SemVer precedence. Equal versions and downgrades fail.

Both existing and candidate directories pass the official Omarchy validator.
Linux `RENAME_EXCHANGE` then swaps them atomically, preserving the plugin's
current enablement in Omarchy configuration. If shell rescan fails, A Quo
atomically swaps the exact old directory back and rescans again. If either
rollback operation fails, the command says manual attention is required.

## What the receipt does—and does not do

The local receipt records the plugin ID, version, package SHA-256, signing-key
fingerprint, local persona ID, and installation time. Its main purpose is to
avoid accidentally treating an arbitrary or Git-managed folder as an A Quo
installation and to enforce publisher continuity across key rotation.

It is not public proof, a signature, a trusted timestamp, a safety review, or a
security boundary against code already running as the same desktop user. That
code can modify any same-user local file, including the receipt and persona
database. Stronger witnessed history and trusted install/update consent are
later layers.

## Still required before high-risk or unattended use

- independent source and runtime-risk review;
- trusted freshness and rollback metadata such as TUF;
- release transparency and build provenance such as Sigstore and SLSA;
- trusted install/update consent using already-open file descriptors; and
- recovery behavior for a machine crash immediately after an atomic exchange.

Do not use this prototype as the sole authorization control for high-risk code.
