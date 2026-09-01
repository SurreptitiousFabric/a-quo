use std::path::Path;

use super::command::run_rescan;
use super::lifecycle::UpdateLifecycle;
use crate::Result;

type PackageInspectionHook<'a> = Box<dyn FnOnce(&Path) -> Result<()> + 'a>;
type UpdateBoundaryHook<'a> = Box<dyn FnOnce() -> Result<()> + 'a>;
type UpdateRescanHook<'a> = Box<dyn FnMut() -> std::result::Result<(), String> + 'a>;

pub(crate) struct UpdateTestHooks<'a> {
    after_package_inspection: Option<PackageInspectionHook<'a>>,
    before_final_authorization: Option<UpdateBoundaryHook<'a>>,
    after_exchange_authorization: Option<UpdateBoundaryHook<'a>>,
    rescan: Option<UpdateRescanHook<'a>>,
}

impl<'a> UpdateTestHooks<'a> {
    pub(crate) fn new() -> Self {
        Self {
            after_package_inspection: None,
            before_final_authorization: None,
            after_exchange_authorization: None,
            rescan: None,
        }
    }

    pub(crate) fn after_package_inspection(
        mut self,
        hook: impl FnOnce(&Path) -> Result<()> + 'a,
    ) -> Self {
        self.after_package_inspection = Some(Box::new(hook));
        self
    }

    pub(crate) fn before_final_authorization(
        mut self,
        hook: impl FnOnce() -> Result<()> + 'a,
    ) -> Self {
        self.before_final_authorization = Some(Box::new(hook));
        self
    }

    pub(crate) fn after_exchange_authorization(
        mut self,
        hook: impl FnOnce() -> Result<()> + 'a,
    ) -> Self {
        self.after_exchange_authorization = Some(Box::new(hook));
        self
    }

    pub(crate) fn rescan(
        mut self,
        hook: impl FnMut() -> std::result::Result<(), String> + 'a,
    ) -> Self {
        self.rescan = Some(Box::new(hook));
        self
    }
}

impl UpdateLifecycle for UpdateTestHooks<'_> {
    fn after_package_inspection(&mut self, staged_package: &Path) -> Result<()> {
        match self.after_package_inspection.take() {
            Some(hook) => hook(staged_package),
            None => Ok(()),
        }
    }

    fn before_final_authorization(&mut self) -> Result<()> {
        match self.before_final_authorization.take() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }

    fn after_exchange_authorization(&mut self) -> Result<()> {
        match self.after_exchange_authorization.take() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }

    fn rescan(&mut self, omarchy_shell: &Path) -> std::result::Result<(), String> {
        match self.rescan.as_mut() {
            Some(hook) => hook(),
            None => run_rescan(omarchy_shell),
        }
    }
}
