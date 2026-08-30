#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use a_quo_display::contains_unsafe_display_characters;
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tar::{Builder as TarBuilder, EntryType, Header};
use tempfile::{Builder as TempBuilder, NamedTempFile};

const REGISTRY_SCHEMA: &str = "urn:a-quo:omarchy-corpus-sources:v1";
const OBSERVATION_SCHEMA: &str = "urn:a-quo:omarchy-corpus-build-observation:v1";
const PACKAGE_FORMAT: &str = "omarchy-zstd-tar-v1";
const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
const MAX_GIT_COMMAND_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_GIT_HEADER_BYTES: usize = 512;
const MAX_COMMIT_OBJECT_BYTES: u64 = 1024 * 1024;
const MAX_TREE_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;
const MAX_PATH_BYTES: usize = 255;
const MAX_TREE_DEPTH: usize = 64;
const MAX_SINGLE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TAR_BYTES: u64 = 600 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const ZSTD_LEVEL: i32 = 19;
const RESERVED_INSTALL_RECEIPT: &str = ".a-quo-install.json";

#[derive(Debug, Parser)]
#[command(
    name = "a-quo-omarchy-corpus",
    about = "Build deterministic unsigned Omarchy corpus packages without executing source"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print validated fixture IDs, one per line.
    List {
        #[arg(long)]
        registry: PathBuf,
    },

    /// Print repository ID, URL, and commit for one validated fixture.
    Source {
        #[arg(long)]
        registry: PathBuf,

        #[arg(long)]
        fixture: String,
    },

    /// Build one canonical package from an exact commit in a bare Git repository.
    Build {
        #[arg(long)]
        registry: PathBuf,

        #[arg(long)]
        fixture: String,

        /// Absolute path to the exact Git executable used for object access.
        #[arg(long)]
        git_program: PathBuf,

        /// Absolute path to a bare, non-shallow Git repository with local objects.
        #[arg(long)]
        git_dir: PathBuf,

        /// Exact clean A Quo commit containing this builder.
        #[arg(long)]
        builder_commit: String,

        /// New directory atomically containing package.tar.zst and observation.json.
        #[arg(long)]
        output_directory: PathBuf,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRegistry {
    schema: String,
    sources: Vec<SourceSpec>,
    #[serde(default)]
    relationships: Vec<Relationship>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSpec {
    fixture_id: String,
    repository_id: String,
    repository_url: String,
    source_commit: String,
    source_tree: String,
    source_commit_time: u64,
    manifest: ManifestPin,
    license: LicensePin,
    selection_rationale: String,
    publication: PublicationRecord,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestPin {
    path: String,
    sha256: String,
    plugin_id: String,
    plugin_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LicensePin {
    path: String,
    sha256: String,
    spdx: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationRecord {
    package_bytes: PublicationState,
    permission_record: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PublicationState {
    NotPublished,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Relationship {
    from: String,
    to: String,
    expectation: RelationshipExpectation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RelationshipExpectation {
    EligibleSameIdIncreasingVersion,
    RefuseDowngrade,
    RefusePluginIdChange,
    RefuseEqualVersion,
}

#[derive(Debug, Deserialize)]
struct ManifestSummary {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    id: String,
    version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeEntryKind {
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntry {
    path: String,
    object_id: String,
    mode: u32,
    size: u64,
    kind: TreeEntryKind,
}

#[derive(Debug)]
struct TreeSnapshot {
    entries: Vec<TreeEntry>,
    total_file_bytes: u64,
}

#[derive(Debug, Serialize)]
struct BuildObservation {
    schema: &'static str,
    fixture_id: String,
    selection_rationale: String,
    source_repository: String,
    source_commit: String,
    source_tree: String,
    source_commit_time: u64,
    source_license_spdx: String,
    source_license_sha256: String,
    builder_commit: String,
    package_format: &'static str,
    package_sha256: String,
    package_size: u64,
    canonical_tar_sha256: String,
    canonical_tar_size: u64,
    entries: u64,
    files: u64,
    directories: u64,
    uncompressed_file_bytes: u64,
    executable_files: Vec<String>,
    manifest_sha256: String,
    plugin_id: String,
    plugin_version: String,
    package_signature: &'static str,
    behavioral_analysis: &'static str,
    safety_evaluation: &'static str,
    package_publication: &'static str,
    publication_permission_record: Option<String>,
    git_version: String,
    git_program_sha256: String,
    tar_entry_mtime: u64,
    zstd_content_size: bool,
    zstd_level: i32,
}

struct GitRepository {
    program: PathBuf,
    git_dir: PathBuf,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::List { registry } => {
            let registry = load_registry(&registry)?;
            for source in registry.sources {
                println!("{}", source.fixture_id);
            }
        }
        Commands::Source { registry, fixture } => {
            let registry = load_registry(&registry)?;
            let source = find_source(&registry, &fixture)?;
            println!("{}", source.repository_id);
            println!("{}", source.repository_url);
            println!("{}", source.source_commit);
        }
        Commands::Build {
            registry,
            fixture,
            git_program,
            git_dir,
            builder_commit,
            output_directory,
        } => {
            validate_object_id("builder commit", &builder_commit)?;
            let registry = load_registry(&registry)?;
            let source = find_source(&registry, &fixture)?.clone();
            let repository = GitRepository::open(git_program, git_dir)?;
            let observation =
                build_fixture_directory(&repository, &source, &builder_commit, &output_directory)?;
            println!(
                "built unsigned corpus fixture {}: {}",
                observation.fixture_id, observation.package_sha256
            );
        }
    }
    Ok(())
}

fn load_registry(path: &Path) -> Result<SourceRegistry> {
    let bytes = read_regular_file(path, MAX_REGISTRY_BYTES)
        .with_context(|| format!("cannot read source registry {}", path.display()))?;
    let registry: SourceRegistry =
        serde_json::from_slice(&bytes).context("source registry is not valid strict JSON")?;
    validate_registry(&registry)?;
    Ok(registry)
}

fn validate_registry(registry: &SourceRegistry) -> Result<()> {
    ensure!(
        registry.schema == REGISTRY_SCHEMA,
        "unsupported source registry schema"
    );
    ensure!(
        !registry.sources.is_empty() && registry.sources.len() <= 64,
        "source registry must contain between 1 and 64 fixtures"
    );

    let mut fixture_ids = BTreeSet::new();
    for source in &registry.sources {
        validate_slug("fixture ID", &source.fixture_id)?;
        validate_slug("repository ID", &source.repository_id)?;
        ensure!(
            fixture_ids.insert(source.fixture_id.as_str()),
            "duplicate fixture ID: {}",
            source.fixture_id
        );
        validate_repository_url(&source.repository_url)?;
        validate_object_id("source commit", &source.source_commit)?;
        validate_object_id("source tree", &source.source_tree)?;
        ensure!(
            source.source_commit_time > 0,
            "source commit time must be positive"
        );
        ensure!(
            source.manifest.path == "manifest.json",
            "fixture {} manifest must be root manifest.json",
            source.fixture_id
        );
        validate_source_path(&source.manifest.path)?;
        validate_source_path(&source.license.path)?;
        validate_sha256("manifest SHA-256", &source.manifest.sha256)?;
        validate_sha256("license SHA-256", &source.license.sha256)?;
        validate_safe_text("plugin ID", &source.manifest.plugin_id, 255)?;
        validate_safe_text("plugin version", &source.manifest.plugin_version, 128)?;
        ensure!(
            source.license.spdx == "MIT",
            "initial corpus fixture {} must have the recorded MIT SPDX identifier",
            source.fixture_id
        );
        validate_safe_text(
            "source-selection rationale",
            &source.selection_rationale,
            512,
        )?;
        ensure!(
            source.publication.package_bytes == PublicationState::NotPublished,
            "initial corpus package bytes must remain unpublished"
        );
        if let Some(record) = &source.publication.permission_record {
            validate_safe_text("publication permission record", record, 512)?;
        }
    }

    let mut relationships = BTreeSet::new();
    for relationship in &registry.relationships {
        ensure!(
            fixture_ids.contains(relationship.from.as_str()),
            "relationship names unknown source fixture: {}",
            relationship.from
        );
        ensure!(
            fixture_ids.contains(relationship.to.as_str()),
            "relationship names unknown destination fixture: {}",
            relationship.to
        );
        ensure!(
            relationship.from != relationship.to,
            "relationship cannot refer to one fixture twice"
        );
        ensure!(
            relationships.insert((relationship.from.as_str(), relationship.to.as_str())),
            "a corpus source pair may have only one relationship expectation"
        );
        let from = registry
            .sources
            .iter()
            .find(|source| source.fixture_id == relationship.from)
            .context("validated relationship source disappeared")?;
        let to = registry
            .sources
            .iter()
            .find(|source| source.fixture_id == relationship.to)
            .context("validated relationship destination disappeared")?;
        validate_relationship(relationship.expectation, from, to)?;
    }
    Ok(())
}

fn validate_relationship(
    expectation: RelationshipExpectation,
    from: &SourceSpec,
    to: &SourceSpec,
) -> Result<()> {
    let from_version = Version::parse(&from.manifest.plugin_version)
        .context("relationship source plugin version is not semantic")?;
    let to_version = Version::parse(&to.manifest.plugin_version)
        .context("relationship destination plugin version is not semantic")?;
    match expectation {
        RelationshipExpectation::EligibleSameIdIncreasingVersion => ensure!(
            from.manifest.plugin_id == to.manifest.plugin_id && from_version < to_version,
            "eligible update relationship must retain plugin ID and increase version"
        ),
        RelationshipExpectation::RefuseDowngrade => ensure!(
            from.manifest.plugin_id == to.manifest.plugin_id && from_version > to_version,
            "downgrade relationship must retain plugin ID and decrease version"
        ),
        RelationshipExpectation::RefusePluginIdChange => ensure!(
            from.manifest.plugin_id != to.manifest.plugin_id,
            "plugin-ID-change relationship must name different plugin IDs"
        ),
        RelationshipExpectation::RefuseEqualVersion => ensure!(
            from.manifest.plugin_id == to.manifest.plugin_id
                && from_version == to_version
                && from.source_tree != to.source_tree,
            "equal-version relationship must retain ID/version and change source tree"
        ),
    }
    Ok(())
}

fn find_source<'a>(registry: &'a SourceRegistry, fixture: &str) -> Result<&'a SourceSpec> {
    validate_slug("fixture ID", fixture)?;
    registry
        .sources
        .iter()
        .find(|source| source.fixture_id == fixture)
        .with_context(|| format!("unknown corpus fixture: {fixture}"))
}

fn build_fixture_directory(
    repository: &GitRepository,
    source: &SourceSpec,
    builder_commit: &str,
    output_directory: &Path,
) -> Result<BuildObservation> {
    let parent = validate_new_output_directory(output_directory)?;
    let staging = TempBuilder::new()
        .prefix(".a-quo-omarchy-corpus.")
        .tempdir_in(&parent)
        .with_context(|| {
            format!(
                "cannot create fixture staging directory in {}",
                parent.display()
            )
        })?;
    let package = staging.path().join("package.tar.zst");
    let observation_path = staging.path().join("observation.json");
    let observation = build_fixture(repository, source, builder_commit, &package)?;
    write_json_new(&observation_path, &observation)?;
    sync_parent(staging.path())?;
    renameat_with(
        CWD,
        staging.path(),
        CWD,
        output_directory,
        RenameFlags::NOREPLACE,
    )
    .with_context(|| {
        format!(
            "refusing to replace fixture output directory {}",
            output_directory.display()
        )
    })?;
    sync_parent(&parent)?;
    Ok(observation)
}

fn build_fixture(
    repository: &GitRepository,
    source: &SourceSpec,
    builder_commit: &str,
    package_output: &Path,
) -> Result<BuildObservation> {
    let git_program_sha256 = sha256_path(&repository.program)?;
    let git_version = repository.version()?;
    let snapshot = repository.snapshot(source)?;
    let package = write_package(repository, source, &snapshot, package_output)?;
    ensure!(
        sha256_path(&repository.program)? == git_program_sha256,
        "Git executable changed during corpus build"
    );

    Ok(BuildObservation {
        schema: OBSERVATION_SCHEMA,
        fixture_id: source.fixture_id.clone(),
        selection_rationale: source.selection_rationale.clone(),
        source_repository: source.repository_url.clone(),
        source_commit: source.source_commit.clone(),
        source_tree: source.source_tree.clone(),
        source_commit_time: source.source_commit_time,
        source_license_spdx: source.license.spdx.clone(),
        source_license_sha256: source.license.sha256.clone(),
        builder_commit: builder_commit.to_owned(),
        package_format: PACKAGE_FORMAT,
        package_sha256: package.sha256,
        package_size: package.size,
        canonical_tar_sha256: package.tar_sha256,
        canonical_tar_size: package.tar_size,
        entries: snapshot.entries.len() as u64,
        files: snapshot
            .entries
            .iter()
            .filter(|entry| entry.kind == TreeEntryKind::File)
            .count() as u64,
        directories: snapshot
            .entries
            .iter()
            .filter(|entry| entry.kind == TreeEntryKind::Directory)
            .count() as u64,
        uncompressed_file_bytes: snapshot.total_file_bytes,
        executable_files: snapshot
            .entries
            .iter()
            .filter(|entry| entry.kind == TreeEntryKind::File && entry.mode == 0o100755)
            .map(|entry| entry.path.clone())
            .collect(),
        manifest_sha256: source.manifest.sha256.clone(),
        plugin_id: source.manifest.plugin_id.clone(),
        plugin_version: source.manifest.plugin_version.clone(),
        package_signature: "not_produced",
        behavioral_analysis: "not_performed",
        safety_evaluation: "not_performed",
        package_publication: "not_performed",
        publication_permission_record: source.publication.permission_record.clone(),
        git_version,
        git_program_sha256,
        tar_entry_mtime: 0,
        zstd_content_size: true,
        zstd_level: ZSTD_LEVEL,
    })
}

struct PackageDigest {
    sha256: String,
    size: u64,
    tar_sha256: String,
    tar_size: u64,
}

fn write_package(
    repository: &GitRepository,
    source: &SourceSpec,
    snapshot: &TreeSnapshot,
    output: &Path,
) -> Result<PackageDigest> {
    let parent = output_parent(output)?;
    let mut tar_temporary = NamedTempFile::new_in(&parent)
        .with_context(|| format!("cannot create tar temporary in {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(&parent)
        .with_context(|| format!("cannot create package temporary in {}", parent.display()))?;
    set_file_mode(tar_temporary.as_file(), 0o600)?;
    set_file_mode(temporary.as_file(), 0o644)?;

    let mut observed_manifest = None;
    let mut observed_license = None;
    {
        let mut batch = repository.batch()?;
        let mut archive = TarBuilder::new(tar_temporary.as_file_mut());

        for entry in &snapshot.entries {
            match entry.kind {
                TreeEntryKind::Directory => {
                    let archive_path = format!("{}/", entry.path);
                    let header = canonical_header(&archive_path, EntryType::Directory, 0o755, 0)?;
                    archive
                        .append(&header, io::empty())
                        .with_context(|| format!("cannot append directory {}", entry.path))?;
                }
                TreeEntryKind::File => {
                    let bytes = batch.object(&entry.object_id, "blob", MAX_SINGLE_FILE_BYTES)?;
                    ensure!(
                        bytes.len() as u64 == entry.size,
                        "Git blob size changed between snapshot and package emission"
                    );
                    if entry.path == source.manifest.path {
                        observed_manifest = Some(bytes.clone());
                    }
                    if entry.path == source.license.path {
                        observed_license = Some(bytes.clone());
                    }
                    let mode = if entry.mode == 0o100755 { 0o755 } else { 0o644 };
                    let header =
                        canonical_header(&entry.path, EntryType::Regular, mode, entry.size)?;
                    archive
                        .append(&header, Cursor::new(bytes))
                        .with_context(|| format!("cannot append file {}", entry.path))?;
                }
            }
        }
        archive
            .finish()
            .context("cannot finish canonical tar stream")?;
        let file = archive
            .into_inner()
            .context("cannot release canonical tar writer")?;
        file.flush().context("cannot flush tar temporary")?;
        file.sync_all().context("cannot sync tar temporary")?;
    }

    validate_pinned_files(source, observed_manifest, observed_license)?;
    let tar_size = tar_temporary
        .as_file()
        .metadata()
        .context("cannot stat tar temporary")?
        .len();
    ensure!(
        tar_size <= MAX_TAR_BYTES,
        "canonical tar exceeds product decompressed-stream limit"
    );
    verify_tar_terminator(tar_temporary.path(), tar_size)?;
    let tar_sha256 = sha256_path(tar_temporary.path())?;
    tar_temporary.as_file_mut().seek(SeekFrom::Start(0))?;
    {
        let mut encoder = zstd::stream::write::Encoder::new(temporary.as_file_mut(), ZSTD_LEVEL)
            .context("cannot initialize deterministic zstd encoder")?;
        encoder.include_checksum(true)?;
        encoder.include_dictid(false)?;
        encoder.include_contentsize(true)?;
        encoder.set_pledged_src_size(Some(tar_size))?;
        let copied = io::copy(tar_temporary.as_file_mut(), &mut encoder)?;
        ensure!(
            copied == tar_size,
            "canonical tar changed while compressing"
        );
        let file = encoder.finish().context("cannot finish zstd stream")?;
        file.flush().context("cannot flush package temporary")?;
        file.sync_all().context("cannot sync package temporary")?;
    }
    let size = temporary
        .as_file()
        .metadata()
        .context("cannot stat package temporary")?
        .len();
    ensure!(
        size <= MAX_PACKAGE_BYTES,
        "compressed package exceeds product package-size limit"
    );
    let sha256 = sha256_path(temporary.path())?;
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .with_context(|| format!("refusing to replace package output {}", output.display()))?;
    sync_parent(&parent)?;
    Ok(PackageDigest {
        sha256,
        size,
        tar_sha256,
        tar_size,
    })
}

fn validate_pinned_files(
    source: &SourceSpec,
    manifest: Option<Vec<u8>>,
    license: Option<Vec<u8>>,
) -> Result<()> {
    let manifest = manifest.context("source tree is missing the pinned root manifest")?;
    ensure!(
        manifest.len() as u64 <= MAX_MANIFEST_BYTES,
        "source manifest exceeds product manifest-size limit"
    );
    ensure!(
        sha256_bytes(&manifest) == source.manifest.sha256,
        "source manifest SHA-256 differs from registry pin"
    );
    let summary: ManifestSummary =
        serde_json::from_slice(&manifest).context("source manifest is not valid JSON")?;
    ensure!(
        summary.schema_version == 1,
        "source manifest schemaVersion is not 1"
    );
    ensure!(
        summary.id == source.manifest.plugin_id,
        "source manifest plugin ID differs from registry pin"
    );
    ensure!(
        summary.version == source.manifest.plugin_version,
        "source manifest version differs from registry pin"
    );

    let license = license.context("source tree is missing the pinned license")?;
    ensure!(
        sha256_bytes(&license) == source.license.sha256,
        "source license SHA-256 differs from registry pin"
    );
    Ok(())
}

fn canonical_header(path: &str, entry_type: EntryType, mode: u32, size: u64) -> Result<Header> {
    let mut header = Header::new_ustar();
    header
        .set_path(path)
        .with_context(|| format!("source path is not representable in USTAR: {path}"))?;
    ensure!(
        header.path_bytes().as_ref() == path.as_bytes(),
        "USTAR path encoding changed the source path"
    );
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_size(size);
    header.set_mtime(0);
    header.set_username("")?;
    header.set_groupname("")?;
    header.set_cksum();
    Ok(header)
}

fn verify_tar_terminator(path: &Path, size: u64) -> Result<()> {
    ensure!(
        size >= 1_024 && size.is_multiple_of(512),
        "canonical tar has invalid block length"
    );
    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(-1_024))?;
    let mut terminator = [1_u8; 1_024];
    file.read_exact(&mut terminator)?;
    ensure!(
        terminator.iter().all(|byte| *byte == 0),
        "canonical tar is missing its two zero end blocks"
    );
    Ok(())
}

impl GitRepository {
    fn open(program: PathBuf, git_dir: PathBuf) -> Result<Self> {
        ensure!(program.is_absolute(), "Git program path must be absolute");
        ensure!(
            git_dir.is_absolute(),
            "bare Git directory path must be absolute"
        );
        require_regular_nonsymlink(&program, "Git program")?;
        require_directory_nonsymlink(&git_dir, "bare Git repository")?;
        require_directory_nonsymlink(&git_dir.join("objects"), "Git object directory")?;
        ensure_path_absent(&git_dir.join("commondir"), "Git commondir file")?;
        let alternates = git_dir.join("objects/info/alternates");
        ensure_path_absent(&alternates, "Git objects/info/alternates")?;

        let repository = Self { program, git_dir };
        ensure!(
            repository.run_text(&["rev-parse", "--is-bare-repository"])? == "true",
            "source Git repository must be bare"
        );
        ensure!(
            repository.run_text(&["rev-parse", "--is-shallow-repository"])? == "false",
            "source Git repository must not be shallow"
        );
        ensure!(
            repository.run_text(&["rev-parse", "--show-object-format"])? == "sha1",
            "source Git repository must use SHA-1 object IDs"
        );
        let configuration = repository.run_optional_text(&[
            "config",
            "--local",
            "--name-only",
            "--get-regexp",
            ".*",
        ])?;
        if let Some(configuration) = configuration {
            for key in configuration.lines().map(str::to_ascii_lowercase) {
                ensure!(
                    key != "extensions.partialclone"
                        && !(key.starts_with("remote.") && key.ends_with(".promisor"))
                        && !(key.starts_with("remote.") && key.ends_with(".partialclonefilter")),
                    "refusing partial/promisor Git repository configuration: {key}"
                );
            }
        }
        Ok(repository)
    }

    fn version(&self) -> Result<String> {
        let version = self.run_text(&["--version"])?;
        validate_safe_text("Git version", &version, 256)?;
        Ok(version)
    }

    fn snapshot(&self, source: &SourceSpec) -> Result<TreeSnapshot> {
        let mut batch = self.batch()?;
        let commit = batch.object(&source.source_commit, "commit", MAX_COMMIT_OBJECT_BYTES)?;
        let (tree, commit_time) = parse_commit_object(&commit)?;
        ensure!(
            tree == source.source_tree,
            "source commit tree differs from registry pin"
        );
        ensure!(
            commit_time == source.source_commit_time,
            "source commit time differs from registry pin"
        );
        let mut entries = Vec::new();
        let mut discovered_entries = 0_usize;
        let mut total_file_bytes = 0_u64;
        let mut manifest = None;
        let mut license = None;
        walk_tree(
            &mut batch,
            &source.source_tree,
            "",
            0,
            &mut entries,
            &mut discovered_entries,
            &mut total_file_bytes,
            source,
            &mut manifest,
            &mut license,
        )?;
        ensure!(!entries.is_empty(), "Git source tree is empty");
        ensure!(
            entries.len() == discovered_entries,
            "Git tree traversal entry count is inconsistent"
        );
        validate_global_archive_order(&entries)?;
        validate_pinned_files(source, manifest, license)?;
        Ok(TreeSnapshot {
            entries,
            total_file_bytes,
        })
    }

    fn batch(&self) -> Result<GitBatch> {
        GitBatch::spawn(self)
    }

    fn run_text(&self, arguments: &[&str]) -> Result<String> {
        let (status, bytes) = self.run_command(arguments, MAX_GIT_COMMAND_OUTPUT_BYTES)?;
        ensure!(status.success(), "Git metadata command failed");
        let text = String::from_utf8(bytes).context("Git emitted non-UTF-8 command output")?;
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn run_optional_text(&self, arguments: &[&str]) -> Result<Option<String>> {
        let (status, bytes) = self.run_command(arguments, MAX_GIT_COMMAND_OUTPUT_BYTES)?;
        if status.success() {
            let text = String::from_utf8(bytes).context("Git emitted non-UTF-8 command output")?;
            return Ok(Some(text.trim_end_matches(['\r', '\n']).to_owned()));
        }
        ensure!(
            status.code() == Some(1),
            "Git optional metadata command failed"
        );
        ensure!(
            bytes.is_empty(),
            "failed Git metadata command emitted stdout"
        );
        Ok(None)
    }

    fn base_command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .arg("--no-pager")
            .arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(&self.git_dir);
        command
    }

    fn run_command(
        &self,
        arguments: &[&str],
        maximum: u64,
    ) -> Result<(std::process::ExitStatus, Vec<u8>)> {
        let mut command = self.base_command();
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .context("cannot execute pinned Git program")?;
        let stdout = child
            .stdout
            .take()
            .context("Git stdout pipe is unavailable")?;
        let mut bytes = Vec::new();
        stdout.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Git metadata output exceeds byte limit");
        }
        let status = child.wait()?;
        Ok((status, bytes))
    }
}

struct GitBatch {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl GitBatch {
    fn spawn(repository: &GitRepository) -> Result<Self> {
        let mut command = repository.base_command();
        command
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .context("cannot start bounded Git object reader")?;
        let input = child
            .stdin
            .take()
            .context("Git object stdin pipe is unavailable")?;
        let output = BufReader::new(
            child
                .stdout
                .take()
                .context("Git object stdout pipe is unavailable")?,
        );
        Ok(Self {
            child,
            input,
            output,
        })
    }

    fn object(&mut self, object_id: &str, expected_type: &str, maximum: u64) -> Result<Vec<u8>> {
        validate_object_id("requested Git object", object_id)?;
        self.input.write_all(object_id.as_bytes())?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        let header = read_line_bounded(&mut self.output, MAX_GIT_HEADER_BYTES)?;
        let header = std::str::from_utf8(&header).context("Git batch header is not UTF-8")?;
        let fields: Vec<&str> = header.split_ascii_whitespace().collect();
        ensure!(
            fields.len() == 3,
            "Git batch object is missing or malformed"
        );
        ensure!(
            fields[0] == object_id,
            "Git batch returned a different object ID"
        );
        ensure!(
            fields[1] == expected_type,
            "Git object type mismatch: expected={expected_type} observed={}",
            fields[1]
        );
        let size = fields[2]
            .parse::<u64>()
            .context("Git batch object size is not an integer")?;
        ensure!(
            size <= maximum,
            "Git {expected_type} object exceeds byte limit"
        );
        let length = usize::try_from(size).context("Git object is too large for this platform")?;
        let mut bytes = vec![0_u8; length];
        self.output.read_exact(&mut bytes)?;
        let mut terminator = [0_u8; 1];
        self.output.read_exact(&mut terminator)?;
        ensure!(
            terminator == *b"\n",
            "Git batch object has invalid terminator"
        );
        verify_git_object_id(expected_type, &bytes, object_id)?;
        Ok(bytes)
    }
}

impl Drop for GitBatch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_line_bounded(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        ensure!(line.len() < maximum, "Git batch header exceeds byte limit");
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return Ok(line);
        }
        line.push(byte[0]);
    }
}

fn verify_git_object_id(kind: &str, bytes: &[u8], expected: &str) -> Result<()> {
    let mut hasher = Sha1::new();
    let header = format!("{kind} {}\0", bytes.len());
    hasher.update(header.as_bytes());
    hasher.update(bytes);
    ensure!(
        format!("{:x}", hasher.finalize()) == expected,
        "Git {kind} object bytes do not match their object ID"
    );
    Ok(())
}

fn parse_commit_object(bytes: &[u8]) -> Result<(String, u64)> {
    let mut tree = None;
    let mut committer_time = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix(b"tree ") {
            ensure!(tree.is_none(), "Git commit contains multiple tree headers");
            let value = std::str::from_utf8(value).context("Git tree header is not UTF-8")?;
            validate_object_id("Git commit tree", value)?;
            tree = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix(b"committer ") {
            ensure!(
                committer_time.is_none(),
                "Git commit contains multiple committer headers"
            );
            let fields: Vec<&[u8]> = value
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .collect();
            ensure!(fields.len() >= 3, "Git committer header is malformed");
            let timestamp = std::str::from_utf8(fields[fields.len() - 2])
                .context("Git committer timestamp is not UTF-8")?
                .parse::<u64>()
                .context("Git committer timestamp is not a positive integer")?;
            committer_time = Some(timestamp);
        }
    }
    Ok((
        tree.context("Git commit has no tree header")?,
        committer_time.context("Git commit has no committer header")?,
    ))
}

#[derive(Debug)]
struct RawTreeEntry {
    name: String,
    object_id: String,
    mode: u32,
    kind: TreeEntryKind,
}

fn parse_tree_object(bytes: &[u8], maximum_entries: usize) -> Result<Vec<RawTreeEntry>> {
    let mut position = 0_usize;
    let mut entries = Vec::new();
    let mut previous_key = None;
    let mut names = BTreeSet::new();
    while position < bytes.len() {
        ensure!(
            entries.len() < maximum_entries,
            "Git tree exceeds remaining global entry-count limit"
        );
        let mode_end = bytes[position..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| position + offset)
            .context("Git tree entry has no mode separator")?;
        let mode_text = std::str::from_utf8(&bytes[position..mode_end])
            .context("Git tree mode is not UTF-8")?;
        let mode = u32::from_str_radix(mode_text, 8).context("Git tree mode is not octal")?;
        position = mode_end + 1;
        let name_end = bytes[position..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| position + offset)
            .context("Git tree entry has no name terminator")?;
        let raw_name = &bytes[position..name_end];
        ensure!(!raw_name.is_empty(), "Git tree entry name is empty");
        ensure!(
            raw_name.len() <= MAX_PATH_BYTES,
            "Git tree component exceeds path byte limit"
        );
        ensure!(
            !raw_name.contains(&b'/'),
            "Git tree component contains a slash"
        );
        ensure!(
            names.insert(raw_name.to_vec()),
            "Git tree contains the same basename with conflicting entry types"
        );
        let name = std::str::from_utf8(raw_name)
            .context("Git tree entry name is not UTF-8")?
            .to_owned();
        position = name_end + 1;
        ensure!(
            bytes.len().saturating_sub(position) >= 20,
            "Git tree entry has a truncated object ID"
        );
        let object_id = hex_sha1(&bytes[position..position + 20]);
        position += 20;
        let kind = match mode_text {
            "40000" => TreeEntryKind::Directory,
            "100644" | "100755" => TreeEntryKind::File,
            _ => bail!("unsupported Git tree entry mode: {mode_text}"),
        };
        let mut sort_key = raw_name.to_vec();
        if kind == TreeEntryKind::Directory {
            sort_key.push(b'/');
        }
        if let Some(previous) = &previous_key {
            ensure!(
                *previous < sort_key,
                "Git tree entries are duplicate or unsorted"
            );
        }
        previous_key = Some(sort_key);
        entries.push(RawTreeEntry {
            name,
            object_id,
            mode,
            kind,
        });
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn walk_tree(
    batch: &mut GitBatch,
    tree_id: &str,
    prefix: &str,
    depth: usize,
    entries: &mut Vec<TreeEntry>,
    discovered_entries: &mut usize,
    total_file_bytes: &mut u64,
    source: &SourceSpec,
    manifest: &mut Option<Vec<u8>>,
    license: &mut Option<Vec<u8>>,
) -> Result<()> {
    ensure!(depth <= MAX_TREE_DEPTH, "Git tree exceeds depth limit");
    let tree = batch.object(tree_id, "tree", MAX_TREE_OBJECT_BYTES)?;
    let remaining_entries = MAX_ENTRIES
        .checked_sub(*discovered_entries)
        .context("Git tree exceeds global entry-count limit")?;
    let raw_entries = parse_tree_object(&tree, remaining_entries)?;
    *discovered_entries = (*discovered_entries)
        .checked_add(raw_entries.len())
        .context("Git entry count overflow")?;
    for raw in raw_entries {
        let path = if prefix.is_empty() {
            raw.name
        } else {
            format!("{prefix}/{}", raw.name)
        };
        validate_source_path(&path)?;
        ensure!(
            entries.len() < MAX_ENTRIES,
            "Git tree exceeds entry-count limit"
        );
        match raw.kind {
            TreeEntryKind::Directory => {
                entries.push(TreeEntry {
                    path: path.clone(),
                    object_id: raw.object_id.clone(),
                    mode: raw.mode,
                    size: 0,
                    kind: TreeEntryKind::Directory,
                });
                walk_tree(
                    batch,
                    &raw.object_id,
                    &path,
                    depth + 1,
                    entries,
                    discovered_entries,
                    total_file_bytes,
                    source,
                    manifest,
                    license,
                )?;
            }
            TreeEntryKind::File => {
                let bytes = batch.object(&raw.object_id, "blob", MAX_SINGLE_FILE_BYTES)?;
                let size = bytes.len() as u64;
                *total_file_bytes = total_file_bytes
                    .checked_add(size)
                    .context("Git source byte count overflow")?;
                ensure!(
                    *total_file_bytes <= MAX_TOTAL_FILE_BYTES,
                    "Git tree exceeds total package file-byte limit"
                );
                if path == source.manifest.path {
                    ensure!(
                        manifest.is_none(),
                        "Git source contains duplicate manifest path"
                    );
                    *manifest = Some(bytes.clone());
                }
                if path == source.license.path {
                    ensure!(
                        license.is_none(),
                        "Git source contains duplicate license path"
                    );
                    *license = Some(bytes);
                }
                entries.push(TreeEntry {
                    path,
                    object_id: raw.object_id,
                    mode: raw.mode,
                    size,
                    kind: TreeEntryKind::File,
                });
            }
        }
    }
    Ok(())
}

fn validate_global_archive_order(entries: &[TreeEntry]) -> Result<()> {
    let mut previous = None;
    for entry in entries {
        let key = archive_path(entry);
        if let Some(previous) = &previous {
            ensure!(
                *previous < key,
                "recursive Git tree is not in canonical archive order"
            );
        }
        previous = Some(key);
    }
    Ok(())
}

fn archive_path(entry: &TreeEntry) -> Vec<u8> {
    let mut path = entry.path.as_bytes().to_vec();
    if entry.kind == TreeEntryKind::Directory {
        path.push(b'/');
    }
    path
}

fn hex_sha1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_source_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty(), "source path must not be empty");
    ensure!(
        path.len() <= MAX_PATH_BYTES,
        "source path exceeds byte limit"
    );
    ensure!(!path.starts_with('/'), "source path must be relative");
    ensure!(
        !path.ends_with('/'),
        "source path must not end with a slash"
    );
    ensure!(
        !path.contains('\\'),
        "source path must not contain backslashes"
    );
    ensure!(!path.contains(':'), "source path must not contain colons");
    ensure!(
        !contains_unsafe_display_characters(path),
        "source path contains unsafe display characters"
    );
    for component in path.split('/') {
        ensure!(
            !component.is_empty() && component != "." && component != "..",
            "source path is not normalized"
        );
        ensure!(component != ".git", ".git content is not packageable");
        ensure!(
            component != RESERVED_INSTALL_RECEIPT,
            "A Quo install receipt path is reserved local metadata"
        );
    }
    Ok(())
}

fn validate_new_output_directory(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "output directory path must be absolute");
    ensure_path_absent(path, "fixture output directory")?;
    output_parent(path)
}

fn ensure_path_absent(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect {description}: {}", path.display()))
        }
        Ok(_) => bail!("{description} must not exist: {}", path.display()),
    }
}

fn output_parent(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .context("output path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("cannot create output directory {}", parent.display()))?;
    require_directory_nonsymlink(parent, "output directory")?;
    Ok(parent.to_path_buf())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let parent = output_parent(path)?;
    let mut temporary = NamedTempFile::new_in(&parent).with_context(|| {
        format!(
            "cannot create observation temporary in {}",
            parent.display()
        )
    })?;
    set_file_mode(temporary.as_file(), 0o644)?;
    temporary.write_all(&bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("refusing to replace observation output {}", path.display()))?;
    sync_parent(&parent)
}

fn read_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    require_regular_nonsymlink(path, "input file")?;
    let metadata = fs::metadata(path)?;
    ensure!(metadata.len() <= maximum, "input file exceeds byte limit");
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "input file changed beyond byte limit"
    );
    ensure!(
        fs::metadata(path)?.len() == metadata.len(),
        "input file size changed while reading"
    );
    Ok(bytes)
}

fn require_regular_nonsymlink(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {description}: {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{description} must be a regular non-symlink file"
    );
    Ok(())
}

fn require_directory_nonsymlink(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {description}: {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "{description} must be a non-symlink directory"
    );
    Ok(())
}

fn validate_slug(field: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 96
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric(),
        "{field} must be a lowercase ASCII slug"
    );
    Ok(())
}

fn validate_repository_url(value: &str) -> Result<()> {
    ensure!(
        value.starts_with("https://github.com/")
            && value.len() <= 512
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~:/".contains(&byte)),
        "source repository must be a canonical HTTPS GitHub URL"
    );
    Ok(())
}

fn validate_safe_text(field: &str, value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value.len() <= maximum
            && !contains_unsafe_display_characters(value),
        "{field} is empty, oversized, or unsafe for display"
    );
    Ok(())
}

fn validate_object_id(field: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be a full lowercase SHA-1 Git object ID"
    );
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be a lowercase SHA-256 digest"
    );
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_path(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("cannot sync output directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_entry(mode: &str, name: &[u8], object_byte: u8) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(mode.as_bytes());
        entry.push(b' ');
        entry.extend_from_slice(name);
        entry.push(0);
        entry.extend_from_slice(&[object_byte; 20]);
        entry
    }

    #[test]
    fn raw_tree_object_accepts_canonical_supported_entries() {
        let mut tree = tree_entry("40000", b"bin", 0x11);
        tree.extend(tree_entry("100644", b"manifest.json", 0x22));
        tree.extend(tree_entry("100755", b"run", 0x33));

        let entries = parse_tree_object(&tree, MAX_ENTRIES).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "bin");
        assert_eq!(entries[0].kind, TreeEntryKind::Directory);
        assert_eq!(entries[1].mode, 0o100644);
        assert_eq!(entries[2].mode, 0o100755);
        assert_eq!(entries[2].object_id, "33".repeat(20));
    }

    #[test]
    fn raw_tree_object_rejects_links_bad_names_and_bad_order() {
        for tree in [
            tree_entry("120000", b"link", 0x11),
            tree_entry("160000", b"submodule", 0x22),
            tree_entry("100644", b"nested/name", 0x33),
            tree_entry("100644", b"non-utf8-\xff", 0x44),
            {
                let mut bytes = tree_entry("100644", b"z", 0x55);
                bytes.extend(tree_entry("100644", b"a", 0x66));
                bytes
            },
            {
                let mut bytes = tree_entry("100644", b"same", 0x77);
                bytes.extend(tree_entry("100644", b"same", 0x88));
                bytes
            },
            {
                let mut bytes = tree_entry("100644", b"same", 0x99);
                bytes.extend(tree_entry("100644", b"same.", 0xab));
                bytes.extend(tree_entry("40000", b"same", 0xaa));
                bytes
            },
        ] {
            assert!(parse_tree_object(&tree, MAX_ENTRIES).is_err());
        }
    }

    #[test]
    fn raw_tree_object_honors_remaining_global_entry_budget() {
        let mut tree = tree_entry("100644", b"a", 0x11);
        tree.extend(tree_entry("100644", b"b", 0x22));
        assert!(parse_tree_object(&tree, 1).is_err());
        assert!(parse_tree_object(&tree, 2).is_ok());
    }

    #[test]
    fn raw_commit_object_pins_tree_and_committer_time() {
        let commit = format!(
            "tree {}\nparent {}\nauthor Example <example@example.test> 12 +0000\ncommitter Example <example@example.test> 34 +0000\n\nmessage\n",
            "a".repeat(40),
            "b".repeat(40)
        );
        assert_eq!(
            parse_commit_object(commit.as_bytes()).unwrap(),
            ("a".repeat(40), 34)
        );
        assert!(parse_commit_object(b"tree invalid\n\nmessage\n").is_err());
    }

    #[test]
    fn git_object_bytes_must_match_requested_sha1() {
        verify_git_object_id(
            "blob",
            b"hello\n",
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )
        .unwrap();
        assert!(
            verify_git_object_id(
                "blob",
                b"goodbye\n",
                "ce013625030ba8dba906f756967f9e9ca394464a"
            )
            .is_err()
        );
    }

    #[test]
    fn source_paths_reject_reserved_and_ambiguous_forms() {
        for path in [
            "",
            "/absolute",
            "../parent",
            "dot/./entry",
            "double//entry",
            "trail/",
            ".git/config",
            "plugin/.a-quo-install.json",
            "windows\\path",
            "drive:path",
            "line\nbreak",
        ] {
            assert!(validate_source_path(path).is_err(), "accepted {path:?}");
        }
        assert!(validate_source_path("assets/Cafe\u{301}.png").is_ok());
    }

    #[test]
    fn canonical_headers_discard_source_ownership_and_extra_mode_bits() {
        let header = canonical_header("bin/run", EntryType::Regular, 0o755, 7).unwrap();
        assert_eq!(header.path().unwrap(), Path::new("bin/run"));
        assert_eq!(header.mode().unwrap(), 0o755);
        assert_eq!(header.uid().unwrap(), 0);
        assert_eq!(header.gid().unwrap(), 0);
        assert_eq!(header.size().unwrap(), 7);
        assert_eq!(header.mtime().unwrap(), 0);
        assert_eq!(header.username().unwrap(), Some(""));
        assert_eq!(header.groupname().unwrap(), Some(""));
    }

    #[test]
    fn strict_registry_rejects_unknown_fields_and_duplicate_sources() {
        let source = serde_json::json!({
            "fixture_id": "example-1",
            "repository_id": "example",
            "repository_url": "https://github.com/example/plugin",
            "source_commit": "a".repeat(40),
            "source_tree": "b".repeat(40),
            "source_commit_time": 1,
            "manifest": {
                "path": "manifest.json",
                "sha256": "c".repeat(64),
                "plugin_id": "example.plugin",
                "plugin_version": "1.0.0"
            },
            "license": {
                "path": "LICENSE",
                "sha256": "d".repeat(64),
                "spdx": "MIT"
            },
            "selection_rationale": "Synthetic registry parser test",
            "publication": {
                "package_bytes": "not_published",
                "permission_record": null
            }
        });
        let valid = serde_json::json!({
            "schema": REGISTRY_SCHEMA,
            "sources": [source.clone()],
            "relationships": []
        });
        let parsed: SourceRegistry = serde_json::from_value(valid).unwrap();
        validate_registry(&parsed).unwrap();

        let duplicate = serde_json::json!({
            "schema": REGISTRY_SCHEMA,
            "sources": [source.clone(), source],
            "relationships": []
        });
        let parsed: SourceRegistry = serde_json::from_value(duplicate).unwrap();
        assert!(validate_registry(&parsed).is_err());

        let unknown = serde_json::json!({
            "schema": REGISTRY_SCHEMA,
            "sources": [],
            "relationships": [],
            "surprise": true
        });
        assert!(serde_json::from_value::<SourceRegistry>(unknown).is_err());
    }

    #[test]
    fn committed_layer_1a_registry_is_exact_and_scanner_free() {
        let mut registry: SourceRegistry = serde_json::from_str(include_str!(
            "../../../fixtures/omarchy/corpus-v1/sources.json"
        ))
        .unwrap();
        validate_registry(&registry).unwrap();

        let fixture_ids: Vec<&str> = registry
            .sources
            .iter()
            .map(|source| source.fixture_id.as_str())
            .collect();
        assert_eq!(
            fixture_ids,
            [
                "cointoss-0-1-0",
                "frame-0-5-0",
                "frame-0-5-1",
                "frame-0-6-0-id-change",
                "frame-0-6-0-current",
                "sonarchy-4-1-0",
            ]
        );
        assert!(registry.sources.iter().all(|source| {
            source.repository_id != "plug-and-prejudice"
                && source.publication.package_bytes == PublicationState::NotPublished
                && source.publication.permission_record.is_none()
        }));
        assert_eq!(registry.relationships.len(), 4);

        registry.relationships.push(Relationship {
            from: "frame-0-5-0".to_owned(),
            to: "frame-0-5-1".to_owned(),
            expectation: RelationshipExpectation::RefusePluginIdChange,
        });
        assert!(validate_registry(&registry).is_err());
    }
}
