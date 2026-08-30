# Threat model

## Assets

- the user's ability to authorize a signature;
- persona separation and privacy;
- private signing keys and wallet-held credentials;
- the exact bytes and human-readable intent being signed;
- trust policies, key history, and revocation history;
- verifier accuracy and understandable failure reporting.

## Adversaries

- a malicious or compromised Omarchy plugin;
- a hostile file, archive, proof bundle, website, or media object;
- a publisher whose key is valid but whose software is malicious;
- a compromised signing key or CI workflow;
- a verifier tricked by stale, ambiguous, or substituted content;
- a service trying to correlate otherwise separate personas;
- malware operating as the same desktop user.

## Required properties

- Signing requires an unambiguous statement, selected persona, artifact digest,
  and explicit consent in a process outside the caller's UI surface.
- The Linux consent protocol is a closed, versioned Unix-socket protocol with
  bounded fields, exactly one passed file descriptor, kernel peer credentials,
  and fail-closed handling of unknown message types or trailing bytes.
- The reviewed artifact is a size-bounded sealed memfd snapshot. Caller paths,
  names, size claims, and mutable descriptors are never the signing authority.
- Signer selection requires one active persona key, an explicitly bound local
  locator revalidated at use time, and post-sign verification against the
  registered public key before a proof is released.
- A trusted routine rotation requires an explicit caller-supplied root digest,
  exact expected sequence and prior head, direct consent showing both key
  fingerprints and the statement digest, and valid old- and new-key signatures
  over identical canonical bytes.
- The routine-rotation proof, old-key retirement, new-key enrollment/binding,
  lifecycle events, and compare-and-swap head advance commit in one local
  transaction before a proof is released. Only an exact committed retry may
  recover a proof after a lost response.
- Live recovery-policy adoption requires independently supplied root,
  latest-policy, and exact current-head pins. Policy proofs form an immutable
  exact-prefix journal with a separate compare-and-swap head.
- Persona-root distribution keeps the signed proof, unsigned public card, and
  unsigned verifier-owned pin record as separate bounded canonical objects.
  The card is derived from a verified proof but embeds neither its public key
  nor its signature. Comparison verifies the proof, derives the expected card,
  and then compares the separately retained pin.
- Root first contact requires an explicit choice among
  `trust_on_first_use`, `same_channel_copy`, and
  `out_of_band_user_confirmed`. Same-channel copying is never presented as
  independent confirmation, while out-of-band separation is reported only as
  `user_reported_separate`. A pin mismatch fails without overwriting or
  silently repinning the old observation; ordinary re-verification is
  read-only with respect to that record.
- The digest-only persona-root QR URI is inert input. Scanning it cannot create
  or replace a pin, import or activate a persona, open a wallet, contact a
  network service, or authorize an operation.
- A recovery/compromise transition requires the active latest policy and exact
  previous head. The proof, old-key lifecycle change, audit events, new-key
  enrollment and signer binding, and continuity-head advance commit in one
  local transaction. A retry of the same canonical statement returns the first
  committed proof wrapper rather than appending duplicate history.
- The bounded recovery-transition ceremony treats its coordinator and transport
  as untrusted. Its canonical request contains the complete public root, policy,
  and prior mixed-transition evidence plus explicit root/latest-policy/previous-
  head expectations, successor public key, and a statement with a signed random
  ID and expiry. It contains no local persona UUID or signer locator.
- Each recovery participant supplies the three expectations independently. The
  Linux daemon reverifies the complete request, derives the authorized role
  from the participant key, and obtains direct-Wayland consent over the
  ceremony, keys, role, pins, reason, expiry, and exact request digest. The
  participant's local signer locator crosses only the private Unix socket and
  is absent from the portable response and prompt.
- Each participant response contains two purpose-separated signatures: the
  existing signature over the recovery-transition statement and a request-
  binding signature over the exact canonical request. Both are verified before
  deterministic assembly into the unchanged recovery proof. Starting,
  responding, and assembly do not mutate a store; commit or recovery archive
  activation remains a separate authority boundary.
- Responding, assembly, and first authority-creating use must occur before the
  signed ceremony expiry. A first live commit of that candidate, or its use as
  the new recovery archive activation extension, rechecks expiry while its
  pinned head and policy remain current. Exact replay of an already committed
  transition or sealed activation receipt may succeed later only without signer
  I/O or new authority; its original recorded time is revalidated against the
  signed expiry.
- Recovery-policy statement v1 authorizes only a replacement with proven
  successor custody. Statement v2 grants terminal authority only through the
  explicit signed `terminal_revocation` capability; existing v1 authorities
  are never given that destructive power retroactively.
- A terminal revocation is a distinct threshold-signed final leaf bound to the
  exact persona, root, latest policy, previous head, and current key. It has no
  successor field or signature. Its first commit atomically deauthorizes the
  current key, removes its signer reference, records the immutable proof, and
  freezes transition and policy mutation for that persona. Exact replay grants
  no authority and returns the first committed wrapper.
- Verification is offline-capable and never executes the signed artifact.
- Parsers have size limits and reject unknown critical fields.
- Persona-backup versions are closed and independently bounded. V2 structurally
  validates and internally reverifies every supplied root, recovery-policy, and
  routine/recovery transition proof before atomically preserving it as
  quarantined evidence. V3 adds an optional terminal proof that must be the
  verified final event, with zero active keys; it still installs no operational
  authority. Limit failures never produce a truncated backup or a partial
  import.
- Archive comparison fully reverifies one selected archive, requires separately
  supplied exact root, effective-head, and explicit latest-policy expectations,
  and keeps the four head relations distinct: exact, extension beyond the pin,
  divergence at or before the pin, and shorter/inconclusive. Every successful
  result remains quarantined with current signer custody and signing authority
  both false; comparison never chooses a longest branch or changes local state.
- Direct archive activation is a separate authority-creating gate. It accepts
  only an already-imported nonterminal archive and requires exact archive,
  root, effective-head, latest-policy, and derived-current-key expectations.
  The first activation ignores imported signer metadata, requires an explicit
  local provider and canonical absolute locator, and proves fresh custody of
  the exact derived key before beginning the write transaction.
- The direct-activation writer uses an immediate transaction, reverifies the
  stored archive and all expectations, detects signer-target replacement,
  records the pending intent before projecting history, and seals only after
  the exact live root, policy, transition, lifecycle, signer, and receipt state
  fully validates. Every injected pre-seal failure rolls back to archive-only
  evidence. The immutable source archive remains retained.
- Exact direct-activation replay requires the same pins and current key,
  performs no signer I/O, and returns the first receipt without repeating
  authority effects. A supplied replay provider or locator must match the
  receipt textually; any changed request conflicts before opening a signer.
  Reports separate historical custody at materialization from a challenge on
  the current invocation.
- Terminal archive hydration is a separate, explicitly selected zero-authority
  gate. It accepts only one already-imported terminal v3 archive and requires
  exact archive, independently supplied root, unique final-terminal-head, and
  exact latest-policy expectations. The preterminal SQL head cannot satisfy the
  head pin. The request has no current-key, signer, provider, locator, recovery-
  proof, `--latest`, or `--force` input.
- The terminal-hydration writer fully reverifies the unique final proof and its
  historical authorization, then uses one immediate transaction to record the
  pending intent, project the root, policy chain, nonterminal prefix,
  preterminal head, and terminal overlay, and seal only after the complete
  zero-authority result validates. Schema v10 permits that overlay insertion
  only for the matching pending terminal-hydration receipt. The immutable source
  archive remains retained; every injected pre-commit failure restores exact
  quarantine.
- A hydrated result is `TerminallyRevoked`, never `Operational`, with zero
  active keys and signer references. Hydration performs no custody check,
  grants no signing or recovery authority, and creates no reactivation path. An
  exact retry is read-only, while changed pins or mode conflict. Later policy
  expiry does not block recording a historically authorized permanent
  deauthorization.
- Embedded C2PA media is parsed only in a separate no-network Linux namespace
  from a hash-checked sealed snapshot; it never enters the signing daemon or
  consent process.
- Sigstore bundles and trusted roots are parsed only in a separate no-network
  Linux namespace from hash-checked sealed snapshots; only the artifact digest,
  not artifact bytes, enters the crypto worker.
- Security-facing text rejects control characters, Unicode line/paragraph
  separators, and every code point in Unicode 17.0's
  `Default_Ignorable_Code_Point` property. That includes bidirectional controls,
  zero-width space/joiners, word joiner, and variation selectors. Ordinary
  combining marks and visible emoji remain allowed, but sequences that require
  default-ignorable shaping controls are rejected because consent and
  verification surfaces may render them differently. This rule does not detect
  visible homoglyphs.
- Stored persona labels and lifecycle actor, policy, and note fields are checked
  again when read, so data accepted by an older policy cannot silently enter a
  newer evidence surface.
- Rejected untrusted values included in terminal-facing diagnostics are bounded
  and byte-escaped to printable ASCII; raw control, separator, and formatting
  characters are not echoed on those paths.
- A proof is bound to a domain-separated purpose and exact statement bytes.
- Key identity, legal identity, build provenance, review, and safety are shown as
  distinct facts or unknowns.
- Revocation never rewrites history: the report shows who revoked what, when,
  and under which policy, while saying the credential is no longer valid.
- Persona export excludes private material, hardware-key stubs, signer
  locators, agent configuration, recovery secrets, PINs, and wallet material.
  Evidence-only import never creates a signer binding or grants operational
  signing or recovery authority.

## Known limitations of the first slice

- Signing invokes fixed `/usr/bin/ssh-keygen` on Unix after rejecting symlinks,
  untrusted owners, and group/world-writable files. It clears the subprocess
  environment and restores only a small session/agent allowlist. Correctness of
  the accepted executable and any operating-system askpass implementation
  remains inherited from the operating system. A key-unlock prompt is separate
  from A Quo consent and receives no A Quo evidence or session-bus address.
- The Omarchy adapter invokes fixed `/usr/bin/omarchy-plugin-validate` and
  `/usr/bin/omarchy-shell` paths and rejects symlinks, untrusted owners, and
  group/world-writable command files. Their subprocess environments are cleared;
  the shell rescan receives only a session allowlist plus fixed Omarchy path and
  timeout values. Command correctness is still inherited from the installed
  Omarchy system.
- A persona label in an SSHSIG proof is self-asserted. It is authenticated by
  the signing key but not independently bound to a legal identity.
- Trusted local consent for persona-root creation proves only that the user
  approved that exact fresh root through A Quo's packaged UI. The root remains
  self-asserted, deliberately correlates later persona activity, and has no
  external trust until a verifier independently obtains and pins its statement
  digest. The local journal can compare an explicit root pin but cannot prove
  its source, independence, publication time, or freshness.
- The portable root card is public copied data rather than proof, and the
  verifier pin record is unsigned local state. Same-user replacement or
  rollback can alter either one or falsely relabel pin provenance.
  `out_of_band_user_confirmed` records the user's account of channel separation
  rather than proving it. Root issuance, pin observation, and comparison times
  are untrusted; warnings after 30 days for late first contact and after 365
  days for pin-observation review are reminders, never root expiry. A valid
  matching root still requires separate current-policy and current-head checks.
- Trusted local two-key routine rotation is implemented only on Linux for a
  newly daemon-journaled live history. It can continue after an explicitly
  committed recovery transition, but it does not adopt older file-only roots
  or quarantined evidence archives. The low-level
  `transition-create` command can make valid portable evidence but lacks trusted
  consent, authoritative-journal construction, and atomic local key transfer.
- The routine journal is crash-consistent at its SQLite transaction boundary,
  and a lost post-commit response is recoverable only by exact intent. It is not
  remotely witnessed; same-user filesystem authority can still replace the
  database, withhold a newer history, or misrepresent where a root pin came
  from. A separately obtained sequence/digest head checkpoint lets verification
  reject an older prefix or sibling branch relative to that checkpoint, but
  cannot establish the checkpoint's freshness or exclude later transitions.
  The prototype still needs independent review, packaged lifecycle and
  real-world migration testing, and accessible trusted consent. Transition
  approval fails closed unless its complete fixed review surface fits in a
  known current output of at least 780 by 900 logical pixels; this protects
  against clipped evidence but excludes smaller and some high-scale outputs.
- Threshold recovery policy enrollment and dual-authority-set policy updates
  remain low-level sequential signing workflows. Terminal revocation likewise
  remains a low-level evidence-adoption workflow rather than a guardian
  ceremony. One recovery transition can use the bounded participant-consent
  ceremony, but A Quo does not prove that its keys belong to independent people
  or devices, use hardware, or were reviewed on uncompromised systems. A
  compromised host may still request every signature it can access. Each
  response requires two signer operations over purpose-separated bytes; a FIDO
  participant may therefore need two physical touches. The direct
  `recovery-transition-create` command remains sequential and lacks this
  trusted consent path.

  An existing operational persona can record an independently pinned signed
  policy chain and atomically commit an already-signed recovery or compromise
  transition, whether its proof came from the ceremony or the low-level direct
  command. Commit is evidence adoption, not proof of guardian independence. A
  first commit also requires the configured successor signer to answer a fresh,
  dedicated challenge with the recovery-approved key, and rechecks that locator
  identity before old-key deauthorization. This prevents committing a merely
  safe-looking wrong key path, but cannot guarantee the signer's future
  availability. Exact replay grants no authority and does not access the
  signer. Terminal revocation accepts no successor and is available only under
  an explicitly terminal-capable v2 policy. The ordinary lifecycle command
  still cannot mark the live current head compromised out of band.
- Recovery-policy checkpoints bind exact transition sequence/digest prefixes
  and prevent a superseded policy from authorizing later recoveries in a
  supplied chain. They do not prove that a newer policy or transition was not
  withheld. Root/latest-policy pins still need an independent trusted channel,
  and claimed issuance/expiry times have no trusted timestamp.
- Evidence-only backup v2 can preserve and reverify a supplied signed root,
  policy chain, and mixed routine/recovery transition chain. Backup v3 can also
  preserve an optional final terminal leaf and its zero-current-authority
  lifecycle state, but imported records remain quarantined from the live
  continuity journal. `persona backup-compare` can now compare one such archive
  per invocation with root, effective-head, and explicit policy expectations
  supplied by the caller. A covered matching pin can establish an exact entry
  or an archive extension; a covered mismatch establishes divergence. When the
  archive ends before the pinned sequence, the result is deliberately
  shorter/inconclusive—not a proven prefix—because the later digest reveals
  nothing about the candidate's missing entry. Embedded digests and the chain
  tip derived from that same file are consistency data, not independent pins,
  and A Quo cannot prove that caller-supplied pins came from an independent or
  fresh source. A coherent older backup, a fully signed sibling branch, a
  withheld newer policy or transition, and a compromise omitted from the
  supplied history remain undetectable without evidence held outside the
  backup. Consequently successful import or comparison does not establish
  global currentness, signer custody, signing or recovery authority, or
  freshness. A verified terminal leaf says the supplied branch ended; without
  an independently held checkpoint it does not exclude a coherent older copy or
  withheld sibling branch.
- Archive comparison remains the non-mutating gate tracked by
  [issue #27](https://github.com/SurreptitiousFabric/a-quo/issues/27). The
  [#26 umbrella](https://github.com/SurreptitiousFabric/a-quo/issues/26) now has
  bounded CLI/store prototypes for direct activation under
  [#29](https://github.com/SurreptitiousFabric/a-quo/issues/29), terminal
  hydration under [#28](https://github.com/SurreptitiousFabric/a-quo/issues/28),
  and recovery activation through one exact authorized transition and fresh
  successor custody under
  [#30](https://github.com/SurreptitiousFabric/a-quo/issues/30). Direct
  activation rejects terminal evidence; terminal hydration is the separate
  zero-authority route; recovery activation never authorizes the archived tip.
  No mode chooses between candidates, merges with or overwrites an existing
  live journal, or resolves a fork. All three still need CLI/product hardening,
  sustained contention and resource-exhaustion tests, coverage-guided fuzzing,
  platform fault hardening, and independent security review. Direct and
  recovery activation are explicit low-level authority-adoption operations
  rather than trusted activation consent; terminal hydration requests no
  consent or signer because it grants no authority.
  Schema v9 commits each post-materialization bind/rebind to a non-secret
  canonical-locator digest, validates the event state machine and clock order,
  and refuses operational head reads that bypass full materialization authority
  validation. Schema v10 adds the guarded terminal-overlay insertion path;
  schema v11 binds recovery activation to the exact recovery proof, successor,
  source and result heads, and sealed receipt.
- Direct activation, recovery activation, and terminal hydration allow future
  unsigned backup-export and proof-observation times because they remain
  imported context, but reject signed issuance or imported persona/key/event
  lifecycle claims later than the local materialization time. They also fail on
  clock rollback before archive import. This prevents future-dated imported
  authority and audit rows from entering the live journal, but local wall-clock
  comparison is not a trusted timestamp and does not establish archive
  freshness, pin freshness, global currentness, or current non-revocation.
  First recovery activation additionally requires an active policy and an
  unexpired schema-v2 proof for its new authority-creating extension; exact
  sealed replay may succeed after expiry because it exercises no authority.
  A validated immutable materialization receipt instead permits an expired
  schema-v2 recovery transition inside its exact retained source-archive prefix
  to remain inspectable and migratable as historical evidence. This exception
  never applies to a new activation extension, an ordinary live first commit,
  or a post-prefix recovery transition. Imported `observed_at` or
  materialization metadata is not trusted proof that the historical transition
  originally committed before expiry.
  Terminal hydration may report an expired latest policy because it records
  permanent historical deauthorization rather than exercising current recovery
  authority.
- V1 metadata-only backups remain importable and retain their original meaning:
  they preserve unsigned local lifecycle context and establish no cryptographic
  continuity. No supported backup version contains private keys.
- Continuity, recovery, and backup hostile-byte parsers enforce an outer byte
  limit before deserialization, then closed structural and collection-count
  limits before signature verification. A ceremony request is bounded at 8 MiB
  and, on each full verification pass, caps aggregate embedded root, policy,
  and transition signature work at 2,048 before cryptographic SSHSIG
  verification; the CLI accounts for repeated passes separately.
  Low-level file-based continuity and recovery commands separately cap actual
  repeated signature-verification work at 2,048, with a path-count lower bound
  before I/O and exact parsed signature accounting before crypto. Selected
  live-store journal reads instead
  preflight a 64 MiB aggregate proof bound, structurally parse the complete
  root, policy chain, tagged routine/recovery transition chain, and optional
  terminal leaf, and perform
  one native cryptographic pass under a separate signature-work ceiling, with
  no verifier subprocess per proof. The verified sequence is opaque. An append
  verifies its candidate signatures once into an opaque receipt and reserves
  the serialized candidate against the 64 MiB total before mutation. It still
  reverifies the existing prefix while holding the immediate writer
  transaction, then links the receipt to that exact head without repeating
  candidate checks. Daemon or Omarchy security checkpoints can still
  revalidate separately; safe
  cross-transaction stored-prefix reuse and a request-wide crypto-work budget
  remain hardening work. The parsers are exercised by bounded coverage-guided
  campaigns. Structural proof parsing does not verify a signature. The
  canonical hosted campaign uses AddressSanitizer and LeakSanitizer plus
  time/allocation/RSS caps. A separately named local fallback disables leak
  detection only where running under `ptrace` makes LSan abort.
  Sustained fuzzing and independent security review remain release work.
- There is no general credential-revocation or time-stamping service in the
  first proof version. A terminal persona leaf can permanently deauthorize one
  supplied A Quo persona branch, but it neither revokes government credentials
  nor supplies trusted time, publication, transparency, or global freshness.
- SQLite lifecycle events are protected from ordinary update/delete/replace
  operations. Schema v6 adds explicit replacement guards for lifecycle and
  signer-reference events plus the original continuity roots, heads, and
  transitions. Schema v7 adds immutable recovery-policy rows and policy heads,
  closed tagged transition shapes, and full mixed-journal reverification.
  Schema v8 adds the immutable terminal overlay and guards that freeze both
  heads after a terminal commit. Schema v9 adds immutable materialization
  receipts and guarded archive/live coexistence; schema v10 permits terminal
  overlay insertion only through an exact pending terminal-hydration intent;
  schema v11 permits a recovery result only through the matching pending intent
  and exact recovery-proof receipt.
  Schema v4 also enforces event/key persona ownership, limits duplicate lifecycle
  milestones, and replays history against key state on reads. A process with
  the user's filesystem authority can still replace the database with a
  coherent older or rewritten copy; the events are local context, not
  independently witnessed audit evidence.
- Signer-reference history records that a binding changed but deliberately does
  not retain old paths. The current path is private local metadata, not proof of
  key custody or hardware backing.
- The lower-level `sign` command remains path-based and does not provide the
  daemon's stronger review-to-sign guarantee. The Linux `request-sign` client
  uses an already-open descriptor, positional before/after hashes, and local
  verification of the returned proof. Its direct-Wayland helper must still be
  installed at the fixed root-owned package path; a source checkout therefore
  remains fail-closed.
- The first direct-Wayland UI deliberately has no AT-SPI bridge because that
  would add a session-bus action path to a security decision. It consequently
  lacks screen-reader support. A generally available release needs a reviewed
  accessible interaction that does not let unrelated session processes invoke
  approval actions.
- The root-owned consent helper is still an ordinary Wayland toplevel, not a
  compositor-provided secure-attention or exclusive-display surface. A
  malicious same-session graphical client may be able to overlay, occlude, or
  imitate it without taking keyboard focus while input reaches the real fixed
  controls. The size gate prevents clipped evidence, not hostile overlays. The
  prototype therefore assumes a trustworthy compositor and display path;
  resistance to malicious same-user graphical clients remains release work.
- Unix socket mode and `SO_PEERCRED` reject other users but cannot distinguish
  honest and malicious processes running as the same desktop user. Caller
  executable details are display evidence only; human consent and key policy
  remain the authorization boundary.
- Direct artifact signing with `--persona-id` holds an immediate local
  authorization transaction through signature creation, signer-identity
  revalidation, and no-replace proof publication. This prevents a concurrent
  lifecycle or terminal commit from landing inside that local signing window.
  It does not provide trusted consent; raw `--persona LABEL` signing is an
  unregistered label claim and intentionally has no store-authority meaning.
- Normal listener teardown removes only its own verified socket inode. An
  abrupt process death can leave a stale path; the daemon refuses to unlink it
  automatically until signal-aware cleanup or user socket activation is
  packaged.
- Omarchy packages are copied into private staging before verification and
  extraction. On Linux, fresh install and update seal the package input and
  disable recursive staging cleanup from creation. Fresh install additionally
  binds the candidate plus receipt to a bounded snapshot; pins the
  plugins/staging/candidate roots; validates from the pinned candidate root;
  moves through pinned parents without replacement; and accepts success only
  after rechecking the live inode and tree. A deterministic post-hook source
  recheck covers the tested substitution window, and unwind never recursively
  deletes a replacement path. The kernel rename still resolves its child names:
  a same-user swap after the last check can redirect the actual move, leave a
  wrong tree live, and produce an indeterminate result rather than accepted
  success. Update, rollback, and removal child-name moves share this limitation.
  Malware already running as the same desktop user can still transiently
  modify and restore owner-writable descendants during external validation,
  race Omarchy configuration, or modify installed plugin files, local receipts,
  retained staging, and persona metadata after a verification point.
  The install path safely reads the accepted on-disk version-1 user
  configuration, or the packaged default when the user file is absent. It
  checks only Omarchy's actual plugin-reference locations and refuses a new
  reference observed at its final pre-exposure guard. This does not make the
  check and directory exposure atomic with Omarchy, so it cannot exclude a
  concurrent reference or transient load. That stronger property requires
  Omarchy cooperation through a coordinated transaction or inhibit interface.
- The A Quo install receipt prevents accidental updates of unmanaged or
  Git-managed plugins and records local publisher continuity. It is not signed,
  remotely witnessed, or a defense against same-user malware.
- Package signatures have no trusted timestamp, expiry, transparency witness,
  or TUF freshness metadata yet. Updates require a strictly newer semantic
  version but are not suitable for unattended fetching.
- A domain-control proof is exact-name and short-lived. Only a matching TXT
  RRset validated to a DNSSEC trust anchor establishes authenticated current
  control; an unsigned match is labeled as an observation. CNAME-target data,
  parent and child names, registrant identity, legal ownership, website
  content, historical control, and trusted time remain outside the claim.
- Live domain verification sends the public queried name to the operating
  system's configured recursive resolver over ordinary DNS with TCP fallback.
  DNSSEC protects authenticity, not query confidentiality. Resolver failure,
  timeout, and over-limit responses remain distinct from authenticated absence.
- Archive inspection lists executable files and enforces structural limits; it
  does not statically or dynamically determine whether plugin code is safe.
- C2PA verification is limited to a 128 MiB local embedded asset. The worker
  does not fetch remote or sidecar manifests, check certificate or timestamp
  trust, query revocation, decode or validate CAWG identity, or link the claim
  to an A Quo persona. `valid` therefore means content binding only.
- The C2PA worker is bounded by Linux namespaces, no capabilities, disabled
  nested user namespaces, fixed resource limits, closed output, and a wall
  deadline, but it does not yet use a syscall seccomp allowlist. It inherits the
  correctness of the kernel, fixed system-owned Bubblewrap and `prlimit` tools
  (UID 0, or overflow UID 65534 when root is unmapped), Rust cryptographic
  dependencies, and the C2PA parser.
- Bubblewrap copies the sealed C2PA input into a read-only in-memory sandbox
  file. The 128 MiB cap bounds peak copies, but large video support remains
  deliberately unavailable pending a safer immutable streaming design.
- Sigstore verification requires an owner-supplied trusted-root snapshot. A Quo
  fingerprints it but does not establish its source, freshness, later
  revocations, or suitability for a publisher. No network or TUF update occurs
  inside verification.
- The first Sigstore slice accepts only standardized v0.3 certificate bundles,
  SHA-256 blob signatures or one-signature in-toto Statement v1 envelopes, and
  certificates with verifiable SCTs. Managed-key hints, legacy bundles, other
  digest algorithms, and private trust domains without SCTs are unavailable.
- `sigstore-verify` is isolated to the CLI adapter. Its Rekor and TSA crates
  compile `reqwest` JSON/form client code even with TLS and TUF features
  disabled. A Quo never constructs those clients, and the worker's unshared
  network namespace is the authority preventing network access.
- Sigstore cryptography inherits `sigstore-verify`, `aws-lc-rs`, and AWS-LC.
  Worker isolation limits parser and network blast radius; it cannot establish
  the cryptographic correctness of those implementations.
- Authenticated SLSA fields remain claims. The prototype checks required v1
  shapes and reports builder/build type, but has no independent builder-level,
  source, build-type, or external-parameter expectation policy and therefore
  assigns no SLSA Build level.
- The Sigstore worker uses the same fixed Bubblewrap/prlimit trust assumptions
  and lacks a syscall seccomp allowlist. Artifact snapshots are capped at 512
  MiB even though only their digest enters parsing; larger release artifacts
  are deliberately unsupported.
- An already-enabled plugin may begin loading the explicitly approved update
  when its directory is atomically exchanged. A failed shell rescan restores
  the prior directory, but the approved candidate may have briefly executed.
- The prototype has not completed an external security audit.
