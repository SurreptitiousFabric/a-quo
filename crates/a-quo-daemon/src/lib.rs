//! Per-user A Quo signing daemon.
//!
//! The daemon composes the strict Unix consent transport, immutable artifact
//! snapshots, persona policy, and portable proof core. Approval is a separate
//! interface so no caller-controlled process can silently authorize signing.

#[cfg(target_os = "linux")]
mod approver;
#[cfg(target_os = "linux")]
mod listener;
#[cfg(target_os = "linux")]
mod service;

#[cfg(target_os = "linux")]
pub use a_quo_approval::{ApprovalDecision, ApprovalPrompt};
#[cfg(target_os = "linux")]
pub use approver::{ApproverConfigError, PACKAGED_APPROVER_PATH, ProcessApprovalBackend};
#[cfg(target_os = "linux")]
pub use listener::{ConsentListener, ListenerError};
#[cfg(target_os = "linux")]
pub use service::{
    ApprovalBackend, ApprovalError, ApprovedSubject, DaemonOutcome, FailureClass,
    UnavailableApprovalBackend, handle_connection, process_received_request,
};
