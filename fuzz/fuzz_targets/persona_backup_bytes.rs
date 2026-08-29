#![no_main]

use a_quo_store::{StoreError, parse_persona_backup_bytes, validate_persona_backup};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    match parse_persona_backup_bytes(bytes) {
        Ok(backup) => {
            validate_persona_backup(&backup).unwrap();
            let canonical = serde_json::to_vec(&backup).unwrap();
            assert_eq!(parse_persona_backup_bytes(&canonical).unwrap(), backup);
        }
        Err(error) => assert_safe(error),
    }
});

fn assert_safe(error: StoreError) {
    let rendered = error.to_string();
    assert!(
        rendered
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
        "unsafe diagnostic: {rendered:?}"
    );
    assert!(
        rendered.len() <= 2_048,
        "unbounded diagnostic: {rendered:?}"
    );
}
