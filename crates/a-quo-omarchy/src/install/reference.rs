#[cfg(not(target_os = "linux"))]
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::archive::validate_plugin_id;
use crate::{
    OmarchyError, OmarchyReferenceObservation, PluginReferenceState, Result, ShellConfigSource,
};

const DEFAULT_SHELL_CONFIG: &str = "/usr/share/omarchy/config/omarchy/shell.json";
const MAX_SHELL_CONFIG_BYTES: u64 = 1024 * 1024;

/// Observes whether the exact plugin ID is referenced by the accepted
/// persisted Omarchy configuration.
///
/// The returned digest covers the exact raw bytes parsed. This is a
/// point-in-time file observation, not evidence that the running shell applied
/// the configuration or that the plugin was loaded or unloaded.
pub fn observe_plugin_reference(
    plugins_directory: &Path,
    plugin_id: &str,
) -> Result<OmarchyReferenceObservation> {
    validate_plugin_id(plugin_id)?;
    let Some(omarchy_directory) = plugins_directory.parent() else {
        return Err(OmarchyError::InvalidShellConfiguration(
            "plugins directory has no parent".to_owned(),
        ));
    };
    let config_path = omarchy_directory.join("shell.json");
    let (bytes, observed_config_path, shell_config_source) =
        match read_shell_configuration(omarchy_directory, &config_path)? {
            Some(bytes) => (bytes, config_path, ShellConfigSource::User),
            None => {
                let default_path = Path::new(DEFAULT_SHELL_CONFIG);
                (
                    read_default_shell_configuration(default_path)?,
                    default_path.to_path_buf(),
                    ShellConfigSource::SystemDefault,
                )
            }
        };
    parse_reference_observation(
        plugin_id,
        &bytes,
        &observed_config_path,
        shell_config_source,
    )
}

fn parse_reference_observation(
    plugin_id: &str,
    bytes: &[u8],
    observed_config_path: &Path,
    shell_config_source: ShellConfigSource,
) -> Result<OmarchyReferenceObservation> {
    let config: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "{} is not valid JSON: {error}",
            observed_config_path.display()
        ))
    })?;
    if !config.is_object() || config.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} must be an object with version 1",
            observed_config_path.display()
        )));
    }
    let state = if shell_configuration_references_plugin(&config, plugin_id)? {
        PluginReferenceState::Referenced
    } else {
        PluginReferenceState::NotReferenced
    };
    Ok(OmarchyReferenceObservation {
        plugin_id: plugin_id.to_owned(),
        state,
        shell_config_source,
        shell_config_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

pub(super) fn reject_stale_enabled_configuration(
    plugins_directory: &Path,
    plugin_id: &str,
) -> Result<()> {
    if observe_plugin_reference(plugins_directory, plugin_id)?.state
        == PluginReferenceState::Referenced
    {
        return Err(OmarchyError::StaleEnabledConfiguration(
            plugin_id.to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn reject_referenced_removal(plugins_directory: &Path, plugin_id: &str) -> Result<()> {
    match reject_stale_enabled_configuration(plugins_directory, plugin_id) {
        Err(OmarchyError::StaleEnabledConfiguration(referenced)) => {
            Err(OmarchyError::ReferencedPluginRemoval(referenced))
        }
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn read_shell_configuration(
    omarchy_directory: &Path,
    config_path: &Path,
) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use rustix::fs::{Mode, OFlags, open, openat};

    let directory = open(
        omarchy_directory,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "cannot safely open {}: {error}",
            omarchy_directory.display()
        ))
    })?;
    let descriptor = match openat(
        &directory,
        "shell.json",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(OmarchyError::InvalidShellConfiguration(format!(
                "cannot safely open {}: {error}",
                config_path.display()
            )));
        }
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} must be a regular current-user-owned file that is not group/world writable",
            config_path.display()
        )));
    }
    read_shell_configuration_bytes(file, config_path)
}

#[cfg(not(target_os = "linux"))]
fn read_shell_configuration(
    _omarchy_directory: &Path,
    config_path: &Path,
) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(OmarchyError::Io {
                path: config_path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::SymlinkBoundary(config_path.to_path_buf()));
    }
    let file = File::open(config_path).map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    read_shell_configuration_bytes(file, config_path)
}

fn read_shell_configuration_bytes(file: File, config_path: &Path) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    file.take(MAX_SHELL_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| OmarchyError::Io {
            path: config_path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_SHELL_CONFIG_BYTES {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} exceeds {MAX_SHELL_CONFIG_BYTES} bytes",
            config_path.display()
        )));
    }
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn read_default_shell_configuration(config_path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        config_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "cannot safely open effective default {}: {error}",
            config_path.display()
        ))
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "effective default {} must be a regular root-owned file that is not group/world writable",
            config_path.display()
        )));
    }
    read_shell_configuration_bytes(file, config_path)?.ok_or_else(|| {
        OmarchyError::InvalidShellConfiguration(format!(
            "effective default {} is unavailable",
            config_path.display()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn read_default_shell_configuration(config_path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(config_path).map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::SymlinkBoundary(config_path.to_path_buf()));
    }
    let file = File::open(config_path).map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    read_shell_configuration_bytes(file, config_path)?.ok_or_else(|| {
        OmarchyError::InvalidShellConfiguration(format!(
            "effective default {} is unavailable",
            config_path.display()
        ))
    })
}

fn shell_configuration_references_plugin(
    config: &serde_json::Value,
    plugin_id: &str,
) -> Result<bool> {
    let Some(root) = config.as_object() else {
        return Err(OmarchyError::InvalidShellConfiguration(
            "shell configuration root must be an object".to_owned(),
        ));
    };
    if let Some(bar) = optional_shell_object(root.get("bar"), "bar")? {
        if shell_id_value(bar.get("id"), "bar.id")? == Some(plugin_id) {
            return Ok(true);
        }
        if let Some(layout) = optional_shell_object(bar.get("layout"), "bar.layout")? {
            for section in ["left", "center", "right"] {
                let Some(entries) = optional_shell_array(
                    layout.get(section),
                    match section {
                        "left" => "bar.layout.left",
                        "center" => "bar.layout.center",
                        "right" => "bar.layout.right",
                        _ => unreachable!(),
                    },
                )?
                else {
                    continue;
                };
                for entry in entries {
                    if shell_entry_plugin_id(entry, true, "bar.layout entry")? == Some(plugin_id) {
                        return Ok(true);
                    }
                }
            }
        }
    }
    if let Some(entries) = optional_shell_array(root.get("plugins"), "plugins")? {
        for entry in entries {
            if shell_entry_plugin_id(entry, false, "plugins entry")? == Some(plugin_id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn optional_shell_object<'a>(
    value: Option<&'a serde_json::Value>,
    location: &'static str,
) -> Result<Option<&'a serde_json::Map<String, serde_json::Value>>> {
    match value {
        None => Ok(None),
        Some(serde_json::Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must be an object when present"
        ))),
    }
}

fn optional_shell_array<'a>(
    value: Option<&'a serde_json::Value>,
    location: &'static str,
) -> Result<Option<&'a Vec<serde_json::Value>>> {
    match value {
        None => Ok(None),
        Some(serde_json::Value::Array(value)) => Ok(Some(value)),
        Some(_) => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must be an array when present"
        ))),
    }
}

fn shell_id_value<'a>(
    value: Option<&'a serde_json::Value>,
    location: &'static str,
) -> Result<Option<&'a str>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must be a string when present"
        ))),
    }
}

fn shell_entry_plugin_id<'a>(
    entry: &'a serde_json::Value,
    allow_string: bool,
    location: &'static str,
) -> Result<Option<&'a str>> {
    match entry {
        serde_json::Value::String(value) if allow_string => Ok(Some(value)),
        serde_json::Value::Object(values) => {
            let Some(value) = shell_id_value(values.get("id"), location)? else {
                return Err(OmarchyError::InvalidShellConfiguration(format!(
                    "{location} must contain a string plugin id"
                )));
            };
            Ok(Some(value))
        }
        _ => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must contain a string plugin id"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        OmarchyError, OmarchyReferenceObservation, PluginReferenceState, ShellConfigSource,
    };

    #[test]
    fn shell_reference_detection_matches_only_omarchy_enablement_locations() {
        let plugin_id = "example.signed-plugin";
        for config in [
            json!({"version": 1, "bar": {"id": plugin_id}}),
            json!({"version": 1, "bar": {"layout": {"left": [plugin_id]}}}),
            json!({"version": 1, "bar": {"layout": {"center": [{"id": plugin_id}]}}}),
            json!({"version": 1, "bar": {"layout": {"right": [{"id": plugin_id}]}}}),
            json!({"version": 1, "plugins": [{"id": plugin_id}]}),
        ] {
            assert!(shell_configuration_references_plugin(&config, plugin_id).unwrap());
        }

        let unrelated = json!({
            "version": 1,
            "bar": {
                "id": "omarchy.bar",
                "layout": {
                    "left": [{"id": "other.plugin", "label": plugin_id}],
                    "center": [],
                    "right": []
                },
                "note": plugin_id
            },
            "plugins": [{"id": "other.plugin", "setting": plugin_id}],
            "unrelated": {"id": plugin_id}
        });
        assert!(!shell_configuration_references_plugin(&unrelated, plugin_id).unwrap());

        let disabled_only = json!({
            "version": 1,
            "plugins": [],
            "disabledPlugins": [plugin_id]
        });
        assert!(!shell_configuration_references_plugin(&disabled_only, plugin_id).unwrap());
        let referenced_and_disabled = json!({
            "version": 1,
            "plugins": [{"id": plugin_id}],
            "disabledPlugins": [plugin_id]
        });
        assert!(
            shell_configuration_references_plugin(&referenced_and_disabled, plugin_id).unwrap()
        );

        for malformed in [
            json!([]),
            json!({"version": 1, "bar": []}),
            json!({"version": 1, "bar": {"id": 123}}),
            json!({"version": 1, "bar": {"layout": []}}),
            json!({"version": 1, "bar": {"layout": {"left": {}}}}),
            json!({"version": 1, "bar": {"layout": {"left": [true]}}}),
            json!({"version": 1, "bar": {"layout": {"center": [{"id": 123}]}}}),
            json!({"version": 1, "bar": {"layout": {"right": [{}]}}}),
            json!({"version": 1, "plugins": {}}),
            json!({"version": 1, "plugins": [{"id": true}]}),
            json!({"version": 1, "plugins": [plugin_id]}),
        ] {
            assert!(shell_configuration_references_plugin(&malformed, plugin_id).is_err());
        }
    }

    #[test]
    fn reference_observation_binds_state_source_and_exact_raw_bytes() {
        let plugin_id = "example.signed-plugin";
        let path = Path::new("accepted-shell.json");
        let referenced = br#"{"version":1,"plugins":[{"id":"example.signed-plugin"}]}"#;
        let observation =
            parse_reference_observation(plugin_id, referenced, path, ShellConfigSource::User)
                .unwrap();
        assert_eq!(
            observation,
            OmarchyReferenceObservation {
                plugin_id: plugin_id.to_owned(),
                state: PluginReferenceState::Referenced,
                shell_config_source: ShellConfigSource::User,
                shell_config_sha256: format!("{:x}", Sha256::digest(referenced)),
            }
        );

        let same_meaning_different_bytes =
            br#"{ "version": 1, "plugins": [ { "id": "example.signed-plugin" } ] }"#;
        let reformatted = parse_reference_observation(
            plugin_id,
            same_meaning_different_bytes,
            path,
            ShellConfigSource::SystemDefault,
        )
        .unwrap();
        assert_eq!(reformatted.state, PluginReferenceState::Referenced);
        assert_eq!(
            reformatted.shell_config_source,
            ShellConfigSource::SystemDefault
        );
        assert_ne!(
            observation.shell_config_sha256,
            reformatted.shell_config_sha256
        );

        let serialized = serde_json::to_value(&observation).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 4);
        assert!(serialized.get("config_bytes").is_none());
        assert!(serialized.get("config_path").is_none());
    }

    #[test]
    fn reference_observation_rejects_unmodelled_configuration() {
        let path = Path::new("accepted-shell.json");
        for malformed in [
            br#"not json"#.as_slice(),
            br#"[]"#.as_slice(),
            br#"{"version":2,"plugins":[]}"#.as_slice(),
            br#"{"version":1,"plugins":["example.signed-plugin"]}"#.as_slice(),
        ] {
            assert!(matches!(
                parse_reference_observation(
                    "example.signed-plugin",
                    malformed,
                    path,
                    ShellConfigSource::User,
                ),
                Err(OmarchyError::InvalidShellConfiguration(_))
            ));
        }
    }

    #[test]
    fn public_reference_observer_reuses_the_safe_user_configuration_reader() {
        let (_directory, omarchy) = shell_fixture();
        let plugins = omarchy.join("plugins");
        let bytes = br#"{"version":1,"plugins":[]}"#;
        fs::write(omarchy.join("shell.json"), bytes).unwrap();

        let observation = observe_plugin_reference(&plugins, "example.signed-plugin").unwrap();
        assert_eq!(observation.state, PluginReferenceState::NotReferenced);
        assert_eq!(observation.shell_config_source, ShellConfigSource::User);
        assert_eq!(
            observation.shell_config_sha256,
            format!("{:x}", Sha256::digest(bytes))
        );
        assert!(observe_plugin_reference(&plugins, "../not-a-plugin").is_err());
    }

    fn shell_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempdir().unwrap();
        let omarchy = directory.path().join("omarchy");
        fs::create_dir_all(omarchy.join("plugins")).unwrap();
        (directory, omarchy)
    }

    #[test]
    fn shell_config_read_is_bounded_versioned_and_missing_user_requests_default_fallback() {
        let (_directory, omarchy) = shell_fixture();
        let plugins = omarchy.join("plugins");
        assert!(
            read_shell_configuration(&omarchy, &omarchy.join("shell.json"))
                .unwrap()
                .is_none()
        );

        fs::write(omarchy.join("shell.json"), br#"{"plugins":[]}"#).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));

        fs::write(
            omarchy.join("shell.json"),
            vec![b' '; usize::try_from(MAX_SHELL_CONFIG_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::write(omarchy.join("shell.json"), br#"{"version":1,"plugins":[]}"#).unwrap();
            fs::set_permissions(
                omarchy.join("shell.json"),
                fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            assert!(matches!(
                reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
                Err(OmarchyError::InvalidShellConfiguration(_))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shell_config_special_files_fail_closed_without_blocking() {
        use std::os::unix::fs::symlink;

        use rustix::fs::{CWD, Mode, mkfifoat};

        let (_directory, omarchy) = shell_fixture();
        let plugins = omarchy.join("plugins");
        let config = omarchy.join("shell.json");

        fs::create_dir(&config).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));
        fs::remove_dir(&config).unwrap();

        let target = omarchy.join("target.json");
        fs::write(&target, br#"{"version":1,"plugins":[]}"#).unwrap();
        symlink(&target, &config).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));
        fs::remove_file(&config).unwrap();

        mkfifoat(CWD, &config, Mode::from_bits_truncate(0o600)).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));
    }
}
