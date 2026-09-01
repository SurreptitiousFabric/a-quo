use std::path::Path;

use a_quo_store::PersonaStore;

mod authorization;
#[cfg(test)]
mod test_seam;
#[cfg(test)]
pub(crate) use test_seam::InstallTestHooks;
mod command;
#[cfg(target_os = "linux")]
mod install_transaction;
mod lifecycle;
mod limits;
mod operation;
mod package;
mod receipt;
mod reference;
#[cfg(target_os = "linux")]
mod remove_transaction;
mod staging;
#[cfg(target_os = "linux")]
mod tree;
#[cfg(target_os = "linux")]
mod update_transaction;

use crate::{InstallOutcome, Result, UninstallOutcome, UpdateOutcome};
#[cfg(test)]
pub(crate) use authorization::publisher_persona_id;
pub(crate) use operation::install::install_with_commands;
#[cfg(test)]
pub(crate) use operation::install::{InstallRequest, install_with_test_hooks};
pub(crate) use operation::remove::uninstall_with_commands;
#[cfg(test)]
pub(crate) use operation::remove::{
    uninstall_with_commands_and_quarantine_hook, uninstall_with_rescan,
};
pub(crate) use operation::update::update_with_commands;
#[cfg(test)]
pub(crate) use operation::update::{
    update_with_commands_and_authorization_hook, update_with_rescan,
    update_with_rescan_and_authorization_finalization_hook,
    update_with_rescan_and_staged_package_hook,
};
pub use reference::observe_plugin_reference;

const VALIDATOR: &str = "/usr/bin/omarchy-plugin-validate";
const OMARCHY_SHELL: &str = "/usr/bin/omarchy-shell";
pub(crate) use limits::INSTALL_RECEIPT_NAME;

pub fn install_signed_package(
    package_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    store: &mut PersonaStore,
    plugins_directory: impl AsRef<Path>,
) -> Result<InstallOutcome> {
    install_with_commands(
        package_path.as_ref(),
        proof_path.as_ref(),
        store,
        plugins_directory.as_ref(),
        Path::new(VALIDATOR),
        Path::new(OMARCHY_SHELL),
    )
}

/// Updates one managed plugin while retaining the displaced tree on Linux.
///
/// The bounded prototype performs no automatic recovery purge. Callers must
/// surface [`UpdateOutcome::previous_release_recovery`] after success and the
/// retained-state detail carried by update errors. Retained trees are
/// reverified at the operation boundary, not made permanently immutable.
pub fn update_signed_package(
    package_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    store: &mut PersonaStore,
    plugins_directory: impl AsRef<Path>,
) -> Result<UpdateOutcome> {
    update_with_commands(
        package_path.as_ref(),
        proof_path.as_ref(),
        store,
        plugins_directory.as_ref(),
        Path::new(VALIDATOR),
        Path::new(OMARCHY_SHELL),
    )
}

/// Removes a managed plugin from its live Omarchy plugin-ID path.
///
/// This bounded operation never purges the plugin from disk. Callers must
/// surface [`UninstallOutcome::recovery_quarantine`] and `disk_purge` so users
/// know where the moved directory remains.
pub fn uninstall_managed_plugin(
    plugin_id: &str,
    plugins_directory: impl AsRef<Path>,
) -> Result<UninstallOutcome> {
    uninstall_with_commands(
        plugin_id,
        plugins_directory.as_ref(),
        Path::new(OMARCHY_SHELL),
    )
}
