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
- controls, Unicode line/paragraph separators, or Unicode 17.0
  default-ignorable characters in paths and displayed manifest values;
- symbolic and hard links, devices, FIFOs, and other special entries;
- `.git` content and the reserved `.a-quo-install.json` management receipt;
- entry points that are absent or are not regular archive files; and
- non-zero data following the logical tar end.

Limits are 128 MiB compressed, 600 MiB decompressed stream, 512 MiB total file
content, 128 MiB per file, 4,096 entries, and 64 KiB for `manifest.json`.
Extraction writes each file itself with normalized permissions; it never calls
tar's general-purpose unpack operation.

Rejected archive paths and manifest identifiers are shown only as bounded,
printable-ASCII diagnostics; unsafe or non-UTF-8 bytes are escaped.

## Inspection

```sh
a-quo omarchy inspect RELEASE.tar.zst \
  --proof RELEASE.tar.zst.a-quo-proof.json
```

Inspection verifies the proof against the exact archive bytes observed at that
step and parses the archive without extracting it. The current standalone path
reopens the caller-supplied pathname for parsing, so it does not yet prove that
the parser saw those same bytes if another same-user process changes the path.
If the persona store exists, the report states
whether the signing key is unrecognized, operational, retired, compromised,
terminally revoked, archived/non-operational, or evidence-only/quarantined, and
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

The closed archive dialect accepts only regular files and directories through
raw tar iteration. GNU long-name/long-link and PAX extension records are
rejected instead of being buffered before A Quo can apply its limits. Each
relative path is limited to 4,096 bytes, 64 components, and 255 bytes per
component; the extracted tree is limited to 8,191 package-derived entries
before A Quo adds its receipt. These are parser/allocation bounds, not a claim
that every maximum-length path is portable to every filesystem.

## First installation

```sh
a-quo omarchy install RELEASE.tar.zst \
  --proof RELEASE.tar.zst.a-quo-proof.json --yes \
  --accept-behavioral-analysis-not-run
```

The current prototype requires two separate CLI acknowledgements before it
mutates plugin state: `--yes` confirms the operation, while
`--accept-behavioral-analysis-not-run` accepts that no behavioural reviewer
analysed what the plugin may do. This is a conservative interim policy gate,
not trusted consent, a review result, or a safety override.

Installation requires an existing persona store, an unarchived operational
persona, an active recognized signing key, and agreement between the signed and
local persona labels. Imported evidence-only continuity never grants this
authority, and a terminally revoked publisher persona can never authorize a
new installation or update even though its historical signatures remain
verifiable.
A Quo copies the package once into a mode-0700 staging directory
under the Omarchy plugins filesystem, then verifies, inspects, extracts, and
validates that staged copy. On Linux the source is opened no-follow and
nonblocking, proved to be a regular file, and copied through a
`MAX_COMPRESSED_BYTES + 1` bound so a FIFO or growing input cannot make the
copy wait or grow without limit.

The fresh-install path currently reopens its staged pathname between phases;
the standalone inspector separately reopens its caller-supplied package path.
They have not yet adopted the sealed-snapshot binding described for Linux
updates below, so same-user path mutation remains a release blocker for those
paths. The final publisher transaction also commits
after the filesystem callback; a late database-finalization failure can leave a
live fresh install while returning an error. Update-only recovery hardening does
not fix either fresh-install boundary.

Before an atomic no-replace move, it checks twice that the plugin ID does not
already exist and is not referenced in the configuration bytes A Quo observes.
Those are pre-move observations, not atomic prevention guarantees. It also
freshly reverifies the publisher disposition, persona lifecycle, key status,
and label. A short SQLite `IMMEDIATE` transaction holds that exact authorization
state across the final atomic move, so a concurrent local retirement,
compromise, or archive cannot slip between the last check and installation.
It writes `.a-quo-install.json` as local management metadata. A release package
cannot provide or overwrite this file.

A Quo makes no Omarchy enable call and does not edit enablement configuration.
Before exposing the directory, the current prototype descriptor-pins and
boundedly reads either a valid current-user `shell.json` or the packaged
root-owned system default. It refuses files with unexpected type or ownership,
group/world writability, malformed plugin-reference entries, and an ID in
Omarchy's exact plugin-reference locations. It does request a shell rescan. The
observation and directory move
are not one Omarchy-owned transaction: another same-user process can change the
configuration between them, and Omarchy may then load the plugin. The result
therefore reports only that A Quo performed no enablement action; it does not
guarantee that the plugin remained unreferenced or was never transiently
loaded. A race-free guarantee requires an Omarchy-coordinated transaction or
inhibit interface.

A shell rescan failure is reported, but the files remain installed so the user
can diagnose or remove them. Explicit enablement remains a separate review
decision.

## Update

```sh
a-quo omarchy update NEWER.tar.zst \
  --proof NEWER.tar.zst.a-quo-proof.json --yes \
  --accept-behavioral-analysis-not-run
```

Update is limited to an existing A Quo-managed, non-Git plugin with a valid
receipt. The candidate must:

- have the same plugin ID;
- be signed by an active key belonging to the same local persona that installed
  the prior release (normal key rotation within that persona is allowed); and
- have strictly greater SemVer precedence. Equal versions and downgrades fail.

The official Omarchy validator returns success for both existing and candidate
directory path observations. A Quo brackets each call with tree snapshots, but
a same-user process can transiently change and restore pathname content during
the external call. The update therefore reports
`passed_path_observation_not_continuous`, not a claim that the validator saw one
immutable tree. Isolation or a descriptor-native validator remains a release
gate.

For the decisions A Quo owns, the installed manifest and management receipt are
opened no-follow/nonblocking and their read bytes must match the SHA-256 and size
in the pinned installed-tree baseline. A transient path cannot therefore change
the installed version or publisher-continuity input and then hide by restoring
the tree.

On Linux, A Quo first copies the staged archive into a kernel-sealed memfd. The
proof descriptor, archive inspection, extraction, and receipt digest all use
that one immutable snapshot rather than reopening its mutable pathname. The
extractor derives a normalized tree manifest from those same sealed bytes. A
Quo adds the exact locally generated receipt, then requires a bounded
descriptor-rooted snapshot of the extracted candidate to match. The snapshot
binds raw relative names, entry types, normalized modes, sizes, and regular-file
SHA-256 values to the package and receipt. A richer operation baseline
additionally records ownership and link counts for both the candidate and
current installed tree.

Automatic temporary-directory cleanup is disabled as soon as Linux update
staging is created, before copying or verifying the package. Early errors can
therefore leave an owner-private recovery directory rather than risk recursively
deleting a same-user replacement at that pathname. A later authorization
refusal retains the unexchanged candidate and reports either its revalidated
staging path or its last observed device/inode when the pathname changed. A Quo
then pins descriptors for the
plugins root, recovery root, installed tree, and candidate. Linux
descriptor-relative `RENAME_EXCHANGE` swaps the two trees without asking
Omarchy to change enablement configuration.

After a successful shell rescan, A Quo revalidates both pinned identities and
both operation baselines. The prior release remains in the private mode-0700
recovery root at the path printed by the command; no automatic disk purge runs.
If the first rescan fails, rollback is attempted only while the pinned prior
tree still matches its baseline. A descriptor-relative exchange restores it,
a second rescan runs, and both resulting trees are revalidated. A verified
rollback leaves the rejected candidate in the reported recovery root. A late
publisher-database finalization failure after exchange follows the same guarded
restore, rescan, and verification path. Changed bytes, permissions, identities,
mappings, or recovery paths produce an indeterminate/manual-attention result
rather than a false success.

These checks establish the retained tree at the verification point. They do
not make owner-writable recovery material permanently immutable; same-user code
can alter it after the command returns. The snapshot does not bind timestamps,
ACLs, extended attributes, or mount identity. There is not yet a durable intent
journal, parent-directory `fsync`, restart reconciliation, or safe purge flow.
Concurrent configuration changes and asynchronous Omarchy reload completion
also remain open hardening work; the current outcome does not claim that
enablement was preserved.

Candidate extraction and permission changes still traverse pathnames beneath
the owner-writable staging root. Same-user malware can substitute an
intermediate directory and cause writes or mode changes outside the intended
staging tree before the final snapshot rejects the candidate. This grants no
new privilege to that same user, but descriptor-relative extraction remains a
release gate for strict side-effect containment.

## Removal

```sh
a-quo omarchy uninstall PLUGIN_ID --yes
```

Removal is limited to an existing non-Git directory whose valid local
`.a-quo-install.json` receipt agrees with its manifest and with the requested
plugin ID. An arbitrary folder is not accepted as managed. The user must first
disable and unreference the plugin in Omarchy; A Quo checks the observed
configuration before preparation and again immediately before the filesystem
change. It makes no Omarchy enablement or configuration change itself.

Publisher authorization is deliberately not required for removal. A user must
remain able to remove a plugin after its publisher key or persona is retired,
compromised, archived, or revoked.

On Linux, A Quo pins descriptors for the plugins directory, managed target, and
mode-0700 recovery quarantine. It uses descriptor-relative `renameat2`, then
verifies that the moved inode is the pinned target before requesting a shell
rescan. If that rescan fails, A Quo reverifies the quarantine entry, attempts a
descriptor-relative exact restore, verifies the restored inode, and rescans
again. A replaced or missing quarantine entry is never restored as though it
were the original.

Even after a successful rescan, this prototype does not recursively delete the
mutable plugin tree. It verifies the retained inode and reported quarantine
path, removes the original from the live plugin-ID path, and returns the exact
recovery-quarantine path. This is an uninstall from the live Omarchy namespace,
not a disk purge. A separately hardened descriptor-relative purge and stale
quarantine recovery flow remain future work. A crash or panic after the atomic
move leaves quarantine retained by default rather than invoking temporary-file
cleanup during unwind.

The result reports only that the configuration A Quo read was unreferenced
before atomic quarantine. A concurrent same-user configuration change or
asynchronous Omarchy reload can still race those observations. Until the
Omarchy-coordinated boundary in issue #33 exists, removal does not prove that
the plugin was disabled, never loaded, or could not be referenced during the
operation. Durable intent records, parent-directory sync, restart reconciliation,
and safe purge remain release gates.

## What the receipt does—and does not do

The local receipt records the plugin ID, version, package SHA-256, signing-key
fingerprint, local persona ID, and installation time. Its main purpose is to
avoid accidentally treating an arbitrary or Git-managed folder as an A Quo
installation and to enforce publisher continuity across key rotation.

It is not public proof, a signature, a trusted timestamp, a safety review, or a
security boundary against code already running as the same desktop user. That
code can modify any same-user local file, including the receipt and persona
database. Stronger witnessed history and trusted install/update/removal consent
are later layers.

## Still required before high-risk or unattended use

- independent source and runtime-risk review;
- trusted freshness and rollback metadata such as TUF;
- release transparency and build provenance such as Sigstore and SLSA;
- trusted install/update/removal consent using already-open file descriptors;
- descriptor-relative candidate extraction and permission changes; and
- durable recovery after a crash immediately after atomic exchange or
  quarantine, plus descriptor- and mount-safe recovery-quarantine purge.

Do not use this prototype as the sole authorization control for high-risk code.
