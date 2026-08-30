#![no_main]

use a_quo_omarchy::risk::{
    RiskContractError, canonical_local_policy_record_bytes, canonical_operation_assessment_bytes,
    canonical_policy_result_record_bytes, canonical_publisher_evidence_record_bytes,
    canonical_structural_record_bytes, canonical_update_delta_record_bytes,
    parse_local_policy_record_bytes, parse_operation_assessment_bytes,
    parse_policy_result_record_bytes, parse_publisher_evidence_record_bytes,
    parse_structural_record_bytes, parse_update_delta_record_bytes,
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
    let mode = match selector {
        b'0'..=b'5' => selector - b'0',
        _ => selector % 6,
    };
    match mode {
        0 => match parse_publisher_evidence_record_bytes(bytes) {
            Ok(value) => assert_eq!(canonical_publisher_evidence_record_bytes(&value).unwrap(), bytes),
            Err(error) => assert_safe(error),
        },
        1 => match parse_structural_record_bytes(bytes) {
            Ok(value) => assert_eq!(canonical_structural_record_bytes(&value).unwrap(), bytes),
            Err(error) => assert_safe(error),
        },
        2 => match parse_update_delta_record_bytes(bytes) {
            Ok(value) => assert_eq!(canonical_update_delta_record_bytes(&value).unwrap(), bytes),
            Err(error) => assert_safe(error),
        },
        3 => match parse_local_policy_record_bytes(bytes) {
            Ok(value) => assert_eq!(canonical_local_policy_record_bytes(&value).unwrap(), bytes),
            Err(error) => assert_safe(error),
        },
        4 => match parse_policy_result_record_bytes(bytes) {
            Ok(value) => assert_eq!(canonical_policy_result_record_bytes(&value).unwrap(), bytes),
            Err(error) => assert_safe(error),
        },
        5 => match parse_operation_assessment_bytes(bytes) {
            Ok(value) => assert_eq!(canonical_operation_assessment_bytes(&value).unwrap(), bytes),
            Err(error) => assert_safe(error),
        },
        _ => unreachable!(),
    }
}

fn assert_safe(error: RiskContractError) {
    let rendered = error.to_string();
    assert!(
        rendered
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
        "unsafe diagnostic: {rendered:?}"
    );
    assert!(rendered.len() <= 512, "unbounded diagnostic: {rendered:?}");
}
