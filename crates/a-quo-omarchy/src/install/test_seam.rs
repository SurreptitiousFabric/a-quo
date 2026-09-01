use std::cell::{Cell, RefCell};
use std::path::Path;

use super::command::run_rescan;
use super::lifecycle::{InstallLifecycle, InstallRescanPhase};
use crate::{OmarchyError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallTestStage {
    Started,
    PackageInspected,
    FinalAuthorization,
    BeforeExposure,
    Exposed,
    InitialRescanFailed,
    RecoveryRescanFailed,
    Finished,
}

type PackageInspectionHook<'a> = Box<dyn FnOnce(&Path) -> Result<()> + 'a>;
type InstallBoundaryHook<'a> = Box<dyn FnOnce() -> Result<()> + 'a>;
type InstallRescanHook<'a> = Box<dyn FnMut() -> std::result::Result<(), String> + 'a>;

pub(crate) struct InstallTestHooks<'a> {
    stage: Cell<InstallTestStage>,
    after_package_inspection: RefCell<Option<PackageInspectionHook<'a>>>,
    before_final_authorization: RefCell<Option<InstallBoundaryHook<'a>>>,
    before_exposure: RefCell<Option<InstallBoundaryHook<'a>>>,
    after_exposure: RefCell<Option<InstallBoundaryHook<'a>>>,
    rescan: RefCell<Option<InstallRescanHook<'a>>>,
}

impl<'a> InstallTestHooks<'a> {
    pub(crate) fn new() -> Self {
        Self {
            stage: Cell::new(InstallTestStage::Started),
            after_package_inspection: RefCell::new(None),
            before_final_authorization: RefCell::new(None),
            before_exposure: RefCell::new(None),
            after_exposure: RefCell::new(None),
            rescan: RefCell::new(None),
        }
    }

    pub(crate) fn after_package_inspection(
        mut self,
        hook: impl FnOnce(&Path) -> Result<()> + 'a,
    ) -> Self {
        assert!(
            self.after_package_inspection.get_mut().is_none(),
            "after-package-inspection hook configured twice"
        );
        *self.after_package_inspection.get_mut() = Some(Box::new(hook));
        self
    }

    pub(crate) fn before_final_authorization(
        mut self,
        hook: impl FnOnce() -> Result<()> + 'a,
    ) -> Self {
        assert!(
            self.before_final_authorization.get_mut().is_none(),
            "before-final-authorization hook configured twice"
        );
        *self.before_final_authorization.get_mut() = Some(Box::new(hook));
        self
    }

    pub(crate) fn before_exposure(mut self, hook: impl FnOnce() -> Result<()> + 'a) -> Self {
        assert!(
            self.before_exposure.get_mut().is_none(),
            "before-exposure hook configured twice"
        );
        *self.before_exposure.get_mut() = Some(Box::new(hook));
        self
    }

    pub(crate) fn after_exposure(mut self, hook: impl FnOnce() -> Result<()> + 'a) -> Self {
        assert!(
            self.after_exposure.get_mut().is_none(),
            "after-exposure hook configured twice"
        );
        *self.after_exposure.get_mut() = Some(Box::new(hook));
        self
    }

    pub(crate) fn rescan(
        mut self,
        hook: impl FnMut() -> std::result::Result<(), String> + 'a,
    ) -> Self {
        assert!(
            self.rescan.get_mut().is_none(),
            "rescan hook configured twice"
        );
        *self.rescan.get_mut() = Some(Box::new(hook));
        self
    }

    fn advance(
        &self,
        expected: &[InstallTestStage],
        next: InstallTestStage,
        callback: &str,
    ) -> Result<()> {
        let current = self.stage.get();
        if !expected.contains(&current) {
            return Err(OmarchyError::InstallStateIndeterminate(format!(
                "test-only install lifecycle callback {callback} is invalid from stage {current:?}"
            )));
        }
        self.stage.set(next);
        Ok(())
    }
}

impl InstallLifecycle for InstallTestHooks<'_> {
    fn after_package_inspection(&self, staged_package: &Path) -> Result<()> {
        self.advance(
            &[InstallTestStage::Started],
            InstallTestStage::PackageInspected,
            "after_package_inspection",
        )?;
        match self.after_package_inspection.borrow_mut().take() {
            Some(hook) => hook(staged_package),
            None => Ok(()),
        }
    }

    fn before_final_authorization(&self) -> Result<()> {
        self.advance(
            &[InstallTestStage::PackageInspected],
            InstallTestStage::FinalAuthorization,
            "before_final_authorization",
        )?;
        match self.before_final_authorization.borrow_mut().take() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }

    fn before_exposure(&self) -> Result<()> {
        self.advance(
            &[InstallTestStage::FinalAuthorization],
            InstallTestStage::BeforeExposure,
            "before_exposure",
        )?;
        match self.before_exposure.borrow_mut().take() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }

    fn after_exposure(&self) -> Result<()> {
        self.advance(
            &[InstallTestStage::BeforeExposure],
            InstallTestStage::Exposed,
            "after_exposure",
        )?;
        match self.after_exposure.borrow_mut().take() {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }

    fn rescan(
        &self,
        omarchy_shell: &Path,
        phase: InstallRescanPhase,
    ) -> std::result::Result<(), String> {
        let next = match (self.stage.get(), phase) {
            (InstallTestStage::Exposed, InstallRescanPhase::Initial) => {
                InstallTestStage::InitialRescanFailed
            }
            (
                InstallTestStage::Exposed | InstallTestStage::InitialRescanFailed,
                InstallRescanPhase::Recovery,
            ) => InstallTestStage::RecoveryRescanFailed,
            (current, phase) => {
                return Err(format!(
                    "test-only install lifecycle callback rescan({phase:?}) is invalid from stage {current:?}"
                ));
            }
        };
        self.stage.set(next);
        let result = match self.rescan.borrow_mut().as_mut() {
            Some(hook) => hook(),
            None => run_rescan(omarchy_shell),
        };
        if result.is_ok() {
            self.stage.set(InstallTestStage::Finished);
        }
        result
    }
}

#[test]
fn records_the_complete_callback_order() {
    let events = RefCell::new(Vec::new());
    let hooks = InstallTestHooks::new()
        .after_package_inspection(|_| {
            events.borrow_mut().push("after_package_inspection");
            Ok(())
        })
        .before_final_authorization(|| {
            events.borrow_mut().push("before_final_authorization");
            Ok(())
        })
        .before_exposure(|| {
            events.borrow_mut().push("before_exposure");
            Ok(())
        })
        .after_exposure(|| {
            events.borrow_mut().push("after_exposure");
            Ok(())
        })
        .rescan(|| {
            events.borrow_mut().push("initial_rescan");
            Ok(())
        });

    InstallLifecycle::after_package_inspection(&hooks, Path::new("staged-package")).unwrap();
    InstallLifecycle::before_final_authorization(&hooks).unwrap();
    InstallLifecycle::before_exposure(&hooks).unwrap();
    InstallLifecycle::after_exposure(&hooks).unwrap();
    InstallLifecycle::rescan(
        &hooks,
        Path::new("/usr/bin/true"),
        InstallRescanPhase::Initial,
    )
    .unwrap();

    assert_eq!(
        *events.borrow(),
        [
            "after_package_inspection",
            "before_final_authorization",
            "before_exposure",
            "after_exposure",
            "initial_rescan",
        ]
    );
}

#[test]
fn rejects_early_duplicate_and_impossible_transitions() {
    let hooks = InstallTestHooks::new();
    let early = InstallLifecycle::before_final_authorization(&hooks).unwrap_err();
    assert!(early.to_string().contains("invalid from stage Started"));

    InstallLifecycle::after_package_inspection(&hooks, Path::new("staged-package")).unwrap();
    let duplicate = InstallLifecycle::after_package_inspection(&hooks, Path::new("staged-package"))
        .unwrap_err();
    assert!(
        duplicate
            .to_string()
            .contains("invalid from stage PackageInspected")
    );

    InstallLifecycle::before_final_authorization(&hooks).unwrap();
    let impossible_rescan = InstallLifecycle::rescan(
        &hooks,
        Path::new("/usr/bin/true"),
        InstallRescanPhase::Initial,
    )
    .unwrap_err();
    assert!(impossible_rescan.contains("invalid from stage FinalAuthorization"));
}

#[test]
fn allows_one_recovery_rescan_after_initial_failure() {
    let calls = Cell::new(0_u8);
    let hooks = InstallTestHooks::new().rescan(|| {
        let call = calls.get();
        calls.set(call + 1);
        if call == 0 {
            Err("initial rescan failed".to_owned())
        } else {
            Ok(())
        }
    });
    InstallLifecycle::after_package_inspection(&hooks, Path::new("staged-package")).unwrap();
    InstallLifecycle::before_final_authorization(&hooks).unwrap();
    InstallLifecycle::before_exposure(&hooks).unwrap();
    InstallLifecycle::after_exposure(&hooks).unwrap();

    assert_eq!(
        InstallLifecycle::rescan(
            &hooks,
            Path::new("/usr/bin/true"),
            InstallRescanPhase::Initial,
        )
        .unwrap_err(),
        "initial rescan failed"
    );
    InstallLifecycle::rescan(
        &hooks,
        Path::new("/usr/bin/true"),
        InstallRescanPhase::Recovery,
    )
    .unwrap();
    let duplicate_recovery = InstallLifecycle::rescan(
        &hooks,
        Path::new("/usr/bin/true"),
        InstallRescanPhase::Recovery,
    )
    .unwrap_err();
    assert!(duplicate_recovery.contains("invalid from stage Finished"));
    assert_eq!(calls.get(), 2);
}
