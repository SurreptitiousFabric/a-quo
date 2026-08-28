mod ui;

use std::io::{self, Write as _};

use a_quo_approval::{DecisionResponse, read_prompt, write_decision};
use thiserror::Error;

#[derive(Debug, Error)]
enum ConsentError {
    #[error("command-line arguments are not accepted")]
    Arguments,

    #[error("invalid daemon prompt")]
    Prompt,

    #[error("trusted window is unavailable")]
    Window,

    #[error("cannot return the approval decision")]
    Response,
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr().lock(), "A Quo consent unavailable: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ConsentError> {
    if std::env::args_os().nth(1).is_some() {
        return Err(ConsentError::Arguments);
    }
    let prompt = read_prompt(io::stdin().lock()).map_err(|_| ConsentError::Prompt)?;
    let request_id = prompt.request_id;
    let decision = ui::show(prompt).map_err(|_| ConsentError::Window)?;
    write_decision(
        io::stdout().lock(),
        DecisionResponse {
            request_id,
            decision,
        },
    )
    .map_err(|_| ConsentError::Response)
}
