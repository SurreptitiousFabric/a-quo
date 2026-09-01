use a_quo_store::{PersonaAuthorityDisposition, PersonaStore, StoreError};

#[cfg(target_os = "linux")]
use super::install_transaction::PinnedInstall;
#[cfg(target_os = "linux")]
use super::update_transaction::PinnedUpdate;
use crate::{OmarchyError, PluginInspection, Result};

#[cfg(target_os = "linux")]
pub(super) enum FinalInstallAuthorization {
    Authorized(PinnedInstall),
    Refused {
        pinned: PinnedInstall,
        cause: OmarchyError,
    },
    OperationFailed {
        pinned: PinnedInstall,
        cause: OmarchyError,
        rename_completed: bool,
    },
    FinalizationFailed {
        pinned: PinnedInstall,
        cause: OmarchyError,
    },
}

#[cfg(target_os = "linux")]
pub(super) enum FinalUpdateAuthorization {
    Authorized(PinnedUpdate),
    Refused(OmarchyError),
    OperationFailed(OmarchyError),
    FinalizationFailed {
        pinned: PinnedUpdate,
        cause: OmarchyError,
    },
}
#[cfg(not(target_os = "linux"))]
pub(super) fn with_final_publisher_authorization<T>(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation()
    });
    result.map_err(|error| normalize_final_authorization_error(error, fingerprint))
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(super) fn with_final_install_authorization(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    pinned: PinnedInstall,
    operation: impl FnOnce(&PinnedInstall, &mut bool) -> Result<()>,
    after_exposure: impl FnOnce() -> Result<()>,
) -> FinalInstallAuthorization {
    let mut operation_started = false;
    let mut operation_completed = false;
    let mut rename_completed = false;
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation_started = true;
        operation(&pinned, &mut rename_completed)?;
        operation_completed = true;
        after_exposure()?;
        Ok(())
    });
    let normalized =
        result.map_err(|error| normalize_final_authorization_error(error, fingerprint));
    match (normalized, operation_started, operation_completed) {
        (Ok(()), _, true) => FinalInstallAuthorization::Authorized(pinned),
        (Ok(()), _, false) => FinalInstallAuthorization::OperationFailed {
            pinned,
            cause: OmarchyError::InstallStateIndeterminate(
                "publisher authorization completed without exposing an install".to_owned(),
            ),
            rename_completed,
        },
        (Err(cause), _, true) => FinalInstallAuthorization::FinalizationFailed { pinned, cause },
        (Err(cause), true, false) => FinalInstallAuthorization::OperationFailed {
            pinned,
            cause,
            rename_completed,
        },
        (Err(cause), false, false) => FinalInstallAuthorization::Refused { pinned, cause },
    }
}

#[cfg(target_os = "linux")]
pub(super) fn with_final_update_authorization(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    operation: impl FnOnce() -> Result<PinnedUpdate>,
    after_exchange: impl FnOnce() -> Result<()>,
) -> FinalUpdateAuthorization {
    let mut completed = None;
    let mut operation_started = false;
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation_started = true;
        let pinned = operation()?;
        completed = Some(pinned);
        after_exchange()?;
        Ok(())
    });
    let normalized =
        result.map_err(|error| normalize_final_authorization_error(error, fingerprint));
    match (normalized, completed, operation_started) {
        (Ok(()), Some(pinned), _) => FinalUpdateAuthorization::Authorized(pinned),
        (Ok(()), None, _) => {
            FinalUpdateAuthorization::OperationFailed(OmarchyError::UpdateStateIndeterminate(
                "publisher authorization completed without an update result".to_owned(),
            ))
        }
        (Err(cause), Some(pinned), _) => {
            FinalUpdateAuthorization::FinalizationFailed { pinned, cause }
        }
        (Err(cause), None, true) => FinalUpdateAuthorization::OperationFailed(cause),
        (Err(cause), None, false) => FinalUpdateAuthorization::Refused(cause),
    }
}

fn normalize_final_authorization_error(error: OmarchyError, fingerprint: &str) -> OmarchyError {
    match error {
        OmarchyError::Store(StoreError::PersonaTerminallyRevoked(_)) => {
            OmarchyError::TerminalPublisher(fingerprint.to_owned())
        }
        OmarchyError::Store(StoreError::PersonaArchived(_)) => {
            OmarchyError::ArchivedPublisher(fingerprint.to_owned())
        }
        OmarchyError::Store(StoreError::ContinuityEvidenceOnly(_)) => {
            OmarchyError::EvidenceOnlyPublisher(fingerprint.to_owned())
        }
        OmarchyError::Store(StoreError::PersonaLabelMismatch(_)) => {
            OmarchyError::PublisherLabelMismatch
        }
        OmarchyError::Store(StoreError::InactiveSigningKey(rejected)) => {
            if rejected != fingerprint {
                return OmarchyError::Store(StoreError::InactiveSigningKey(rejected));
            }
            OmarchyError::InactivePublisher {
                fingerprint: rejected,
                status: "inactive",
            }
        }
        error => error,
    }
}

pub(crate) fn publisher_persona_id(
    store: &PersonaStore,
    inspection: &PluginInspection,
) -> Result<String> {
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    let recognized = store
        .lookup_key(fingerprint)?
        .ok_or_else(|| OmarchyError::UnrecognizedPublisher(fingerprint.clone()))?;
    match recognized.authority_disposition {
        PersonaAuthorityDisposition::Operational => {}
        PersonaAuthorityDisposition::EvidenceOnly => {
            return Err(OmarchyError::EvidenceOnlyPublisher(fingerprint.clone()));
        }
        PersonaAuthorityDisposition::TerminallyRevoked => {
            return Err(OmarchyError::TerminalPublisher(fingerprint.clone()));
        }
        PersonaAuthorityDisposition::Archived => {
            return Err(OmarchyError::ArchivedPublisher(fingerprint.clone()));
        }
    }
    if recognized.persona.archived_at.is_some() {
        return Err(OmarchyError::ArchivedPublisher(fingerprint.clone()));
    }
    match recognized.key.status {
        a_quo_store::KeyStatus::Active => {}
        a_quo_store::KeyStatus::Retired => {
            return Err(OmarchyError::InactivePublisher {
                fingerprint: fingerprint.clone(),
                status: "retired",
            });
        }
        a_quo_store::KeyStatus::Compromised => {
            return Err(OmarchyError::InactivePublisher {
                fingerprint: fingerprint.clone(),
                status: "compromised",
            });
        }
    }
    if recognized.persona.label != inspection.artifact_evidence.signer.persona {
        return Err(OmarchyError::PublisherLabelMismatch);
    }
    Ok(recognized.persona.id)
}
