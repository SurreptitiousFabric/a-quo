#![no_main]

use a_quo_core::{
    ProofError, canonical_persona_root_card_bytes, canonical_persona_root_pin_bytes,
    parse_persona_root_card_bytes, parse_persona_root_pin_bytes, parse_persona_root_pin_uri,
    persona_root_pin_uri,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    check_selected(selector, bytes);
    if let Some(stripped) = bytes.strip_suffix(b"\n") {
        check_selected(selector, stripped);
    }
});

fn check_selected(selector: u8, bytes: &[u8]) {
    match selector % 3 {
        0 => check_card(bytes),
        1 => check_pin(bytes),
        2 => check_uri(bytes),
        _ => unreachable!(),
    }
}

fn check_card(bytes: &[u8]) {
    match parse_persona_root_card_bytes(bytes) {
        Ok(card) => assert_eq!(canonical_persona_root_card_bytes(&card).unwrap(), bytes),
        Err(error) => assert_safe(error),
    }
}

fn check_pin(bytes: &[u8]) {
    match parse_persona_root_pin_bytes(bytes) {
        Ok(pin) => assert_eq!(canonical_persona_root_pin_bytes(&pin).unwrap(), bytes),
        Err(error) => assert_safe(error),
    }
}

fn check_uri(bytes: &[u8]) {
    let Ok(uri) = std::str::from_utf8(bytes) else {
        return;
    };
    match parse_persona_root_pin_uri(uri) {
        Ok(digest) => assert_eq!(persona_root_pin_uri(&digest).unwrap(), uri),
        Err(error) => assert_safe(error),
    }
}

fn assert_safe(error: ProofError) {
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
