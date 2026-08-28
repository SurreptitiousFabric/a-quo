# Personas and key history

## What a persona is

A persona is a local compartment for one public role: personal publishing,
pseudonymous work, a project, an organization, or a bridge to a legal-wallet
presentation. Each persona should use independent signing keys. A Quo does not
create a universal identifier connecting them.

The random persona UUID is local metadata. SSHSIG proof v1 publishes the chosen
label and public-key fingerprint, not that UUID. Publishing the same label or
key in several places can still correlate activity, so separation ultimately
depends on the user's key and naming choices.

## What is stored

The SQLite database contains:

- persona UUID, display label, purpose, and local creation/archive time;
- OpenSSH public key, fingerprint, declared provider, and lifecycle status;
- enrollment, rotation, retirement, and compromise events;
- the current local signer path for an explicitly bound key; and
- append-only bind, rebind, and unbind events without historical path copies;
- the recorded actor, local Unix time, policy identifier, and optional note.

It does not accept private keys, PINs, recovery material, wallet credentials,
or credential payloads. On Unix, the database directory must be mode 0700 or
stricter and the database file is set to mode 0600.

The signer path can reveal local filesystem structure, so it stays in the
private local database and is excluded from proofs and ordinary verification
reports. A Quo never copies the referenced private-key or hardware-stub bytes.

## Key providers

`openssh-file` and `ssh-agent` describe how the user intends to access a key;
the public key alone cannot prove where the private key is held. `fido2` is
stricter: A Quo accepts it only for OpenSSH security-key algorithms such as
`sk-ssh-ed25519@openssh.com`. Actual signing still goes through `ssh-keygen`, so
the hardware must participate.

## Signer references

`persona key-bind` attaches an active registered key to an absolute path that
`ssh-keygen` can use. For `openssh-file` this is normally a private key. For
`fido2` it is normally the OpenSSH hardware-key stub. For `ssh-agent` it must be
the corresponding public-key stub; A Quo reads that public file and requires
its fingerprint to match the registered key.

On Unix, A Quo resolves the path, rejects a final symbolic link, requires a
regular file owned by the current user, and rejects group/world writes. Private
and hardware-key stubs cannot grant any group/world permissions; mode 0600 is
typical. A root-owned public agent stub is allowed if it is not group/world
writable. These checks run both when binding and whenever a signer is selected.

Selection fails closed if the persona is archived, has no active key, has more
than one active key, lacks a locator for its sole active key, or the locator no
longer resolves to its bound canonical target. Rotation never lets an old
locator authorize the new key. After signing, the proof core verifies the new
signature against the registered public key before returning it, so a later
wrong-file substitution cannot produce a falsely attributed proof.

The locator and declared provider are operational configuration, not proof of
hardware custody. `persona key-unbind` deletes the current locator while
retaining its non-secret configuration event history.

## Rotation and compromise

Rotation inserts a new active key and changes every prior active key to retired,
or compromised when compromise is the stated reason. It never deletes an old
key or its events. A verifier can therefore say both:

- the historical artifact still has a valid signature; and
- the key is now retired or recorded as compromised under a named local policy.

Registered signing refuses retired and compromised keys before invoking the
signer. Verification does not hide old proofs and never claims a compromised
credential remains currently trusted.

## Limits of local history

SQLite triggers reject ordinary updates and deletes to lifecycle events, but a
same-user attacker can replace the whole database. The history is useful local
context, not a transparency log, trusted timestamp, official revocation source,
or legal identity binding. Later trust-log and issuer adapters must appear as
separate evidence rather than silently upgrading local records.
