use a_quo_store::{PersonaAuthorityDisposition, PersonaStore, StoreError};

use crate::{OmarchyError, PluginInspection, Result};

#[cfg(target_os = "linux")]
pub(super) enum FinalAuthorization<T> {
    Authorized(T),
    Refused(OmarchyError),
    OperationFailed(OmarchyError),
    FinalizationFailed { completed: T, cause: OmarchyError },
    CompletedWithoutValue,
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
pub(super) fn with_final_publisher_operation<T>(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    operation: impl FnOnce() -> Result<T>,
    after_operation: impl FnOnce() -> Result<()>,
) -> FinalAuthorization<T> {
    let mut operation_started = false;
    let mut completed = None;
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation_started = true;
        completed = Some(operation()?);
        after_operation()?;
        Ok(())
    });
    let normalized =
        result.map_err(|error| normalize_final_authorization_error(error, fingerprint));
    match (normalized, completed, operation_started) {
        (Ok(()), Some(completed), _) => FinalAuthorization::Authorized(completed),
        (Ok(()), None, _) => FinalAuthorization::CompletedWithoutValue,
        (Err(cause), Some(completed), _) => {
            FinalAuthorization::FinalizationFailed { completed, cause }
        }
        (Err(cause), None, true) => FinalAuthorization::OperationFailed(cause),
        (Err(cause), None, false) => FinalAuthorization::Refused(cause),
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
