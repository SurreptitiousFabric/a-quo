use std::path::Path;

use super::command::run_rescan;
use crate::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstallRescanPhase {
    Initial,
    Recovery,
}

/// Private install control-flow seam.
///
/// Its callbacks can only observe a boundary or return an error. They cannot
/// supply an authorization result, replace a verified identity, or construct
/// a successful outcome. Production can instantiate only the no-op
/// implementation below; configurable callbacks exist only under `cfg(test)`.
///
/// The complete injection-point inventory is:
///
/// - `after_package_inspection`: challenge the sealed-package/path-substitution
///   invariant after signature and publisher inspection;
/// - `before_final_authorization`: challenge publisher, configuration,
///   candidate-tree, and pinned-parent revalidation before authority is used;
/// - `before_exposure`: challenge the last descriptor-relative source and
///   no-replace destination checks immediately before rename;
/// - `after_exposure`: challenge authorization finalization and final-layout
///   verification after the candidate becomes live; and
/// - `rescan`: inject the initial or recovery rescan result while retaining the
///   existing rollback and recovery-observation behavior.
pub(crate) trait InstallLifecycle {
    fn after_package_inspection(&self, _staged_package: &Path) -> Result<()> {
        Ok(())
    }

    fn before_final_authorization(&self) -> Result<()> {
        Ok(())
    }

    fn before_exposure(&self) -> Result<()> {
        Ok(())
    }

    fn after_exposure(&self) -> Result<()> {
        Ok(())
    }

    fn rescan(
        &self,
        omarchy_shell: &Path,
        _phase: InstallRescanPhase,
    ) -> std::result::Result<(), String> {
        run_rescan(omarchy_shell)
    }
}

/// Private update control-flow seam.
///
/// The callbacks can observe one of the three existing update boundaries or
/// provide the shell-rescan result. They cannot supply authorization,
/// identities, transaction state, or a successful outcome. Production uses a
/// no-op implementation; configurable callbacks exist only under `cfg(test)`.
pub(crate) trait UpdateLifecycle {
    fn after_package_inspection(&mut self, _staged_package: &Path) -> Result<()> {
        Ok(())
    }

    fn before_final_authorization(&mut self) -> Result<()> {
        Ok(())
    }

    fn after_exchange_authorization(&mut self) -> Result<()> {
        Ok(())
    }

    fn rescan(&mut self, omarchy_shell: &Path) -> std::result::Result<(), String> {
        run_rescan(omarchy_shell)
    }
}
