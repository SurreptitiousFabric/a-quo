#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use a_quo_daemon::{
    ApprovalBackend, ConsentListener, DaemonOutcome, ProcessApprovalBackend,
    UnavailableApprovalBackend, handle_connection,
};
#[cfg(target_os = "linux")]
use a_quo_store::PersonaStore;
#[cfg(target_os = "linux")]
use anyhow::{Context, Result, bail, ensure};
#[cfg(target_os = "linux")]
use clap::Parser;

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(
    name = "a-quo-daemon",
    version,
    about = "Private per-user A Quo signing daemon"
)]
struct Cli {
    /// Existing persona database; defaults to the platform data directory.
    #[arg(long, value_name = "PATH")]
    store: Option<PathBuf>,

    /// Validated XDG runtime root under which A Quo creates its private directory.
    #[arg(long, value_name = "DIRECTORY")]
    runtime_directory: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let store_path = resolve_store_path(cli.store.as_deref())?;
    ensure!(
        store_path.is_file(),
        "persona store does not exist: {}",
        store_path.display()
    );
    let mut store = PersonaStore::open(&store_path)
        .with_context(|| format!("cannot open persona store {}", store_path.display()))?;
    let runtime_directory = resolve_runtime_directory(cli.runtime_directory.as_deref())?;
    let listener = ConsentListener::bind(&runtime_directory)?;
    let mut approval: Box<dyn ApprovalBackend> = match ProcessApprovalBackend::packaged() {
        Ok(backend) => {
            eprintln!("Trusted busless approval process is available.");
            Box::new(backend)
        }
        Err(_) => {
            eprintln!("Trusted approval process is unavailable; requests fail closed.");
            Box::new(UnavailableApprovalBackend)
        }
    };

    eprintln!("A Quo consent socket: {}", listener.path().display());
    loop {
        let connection = listener.accept()?;
        let outcome = handle_connection(&connection, &mut store, approval.as_mut());
        match outcome {
            DaemonOutcome::Approved { request_id, .. } => {
                eprintln!("request={request_id} outcome=approved");
            }
            DaemonOutcome::Rejected {
                request_id,
                failure,
            } => {
                eprintln!(
                    "request={} outcome=rejected class={failure:?}",
                    request_id.as_deref().unwrap_or("unavailable")
                );
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("a-quo-daemon is currently available only on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn resolve_runtime_directory(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        ensure!(path.is_absolute(), "runtime directory must be absolute");
        return Ok(path.to_path_buf());
    }
    let value = std::env::var_os("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR is required; or pass --runtime-directory")?;
    let path = PathBuf::from(value);
    ensure!(path.is_absolute(), "XDG_RUNTIME_DIR must be absolute");
    Ok(path)
}

#[cfg(target_os = "linux")]
fn resolve_store_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        let data_home = PathBuf::from(data_home);
        ensure!(data_home.is_absolute(), "XDG_DATA_HOME must be absolute");
        return Ok(data_home.join("a-quo/personas.sqlite3"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local/share/a-quo/personas.sqlite3"));
    }
    bail!("cannot locate the persona store; pass --store PATH")
}
