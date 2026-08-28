use std::io;

use a_quo_approval::{ApprovalPrompt, ArtifactKind, PeerIdentity, PersonaPurpose, write_prompt};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prompt = ApprovalPrompt::new(
        Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf")?,
        Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c")?,
        "A Quo project publisher",
        PersonaPurpose::Project,
        "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8mXY",
        ArtifactKind::SoftwareRelease,
        "a-quo-0.1.0-1-x86_64.pkg.tar.zst",
        [0xab; 32],
        1_234_567,
        PeerIdentity {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        },
    )?;
    write_prompt(io::stdout().lock(), &prompt)?;
    Ok(())
}
