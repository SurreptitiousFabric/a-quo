//! Live, bounded DNS evidence for portable A Quo domain-control proofs.
//!
//! Proof creation and cryptographic verification remain in `a-quo-core`.
//! This crate performs the separate network observation and reports DNSSEC
//! state without turning an unsigned DNS answer into a cryptographic claim.

use std::time::Duration;

use a_quo_core::{
    DomainControlVerification, EvidenceStatus, ProofBundle, ProofError, VerifiedSigner,
    verify_domain_control_proof,
};
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolveHosts, ResolverOpts};
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::dnssec::Proof as HickoryProof;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum wall-clock time spent on one live DNS observation.
pub const DNS_LOOKUP_DEADLINE_SECONDS: u64 = 12;

const DNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_LOOKUP_DEADLINE: Duration = Duration::from_secs(DNS_LOOKUP_DEADLINE_SECONDS);
const DNS_CACHE_TTL_CAP: Duration = Duration::from_secs(300);
const MAX_ANSWER_RECORDS: usize = 64;
const MAX_TXT_RECORD_BYTES: usize = 4 * 1024;
const MAX_TOTAL_TXT_BYTES: usize = 64 * 1024;

/// Whether the exact TXT commitment was present at the exact claimed owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    /// At least one exact-owner TXT record exactly matched the commitment.
    Matched,
    /// No exact-owner TXT record exactly matched the commitment.
    Missing,
}

/// DNSSEC validation state for the relevant positive or negative evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecStatus {
    /// The evidence validates to a configured DNSSEC trust anchor.
    Secure,
    /// The resolver proved that the relevant zone is unsigned.
    Insecure,
    /// The evidence should have validated but did not.
    Bogus,
    /// The resolver could not establish a validation state.
    Indeterminate,
}

/// The deliberately narrow conclusion supported by the current observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainControlStatus {
    /// A current exact publication was authenticated through DNSSEC.
    VerifiedDnssec,
    /// A current exact publication was seen in a provably unsigned zone.
    ObservedUnsigned,
    /// Current authenticated control was not established.
    NotEstablished,
}

/// Combined signature and live DNS evidence for one domain-control proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveDomainControlVerification {
    pub signature: EvidenceStatus,
    pub validity: EvidenceStatus,
    pub publication: PublicationStatus,
    pub dnssec: DnssecStatus,
    pub domain_control: DomainControlStatus,
    pub domain: String,
    pub dns_record_name: String,
    pub dns_txt_value: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub checked_at: i64,
    /// The lowest TTL among exact matching records, when one was observed.
    pub matching_record_ttl_seconds: Option<u32>,
    pub signer: VerifiedSigner,
    pub not_established: Vec<String>,
}

/// A failure to validate the portable proof or obtain bounded DNS evidence.
#[derive(Debug, Error)]
pub enum DomainVerificationError {
    #[error("signed domain-control proof is invalid: {0}")]
    Proof(#[from] ProofError),

    #[error("cannot read the system DNS resolver configuration")]
    ResolverConfiguration,

    #[error("cannot initialize the validating DNS resolver")]
    ResolverInitialization,

    #[error("cannot parse the proof's canonical DNS query name")]
    InvalidQueryName,

    #[error("DNS lookup exceeded the {DNS_LOOKUP_DEADLINE_SECONDS}-second deadline")]
    LookupTimedOut,

    #[error("DNS lookup failed before publication evidence could be established")]
    LookupFailed,

    #[error("DNS response exceeded A Quo's bounded processing limits")]
    ResponseTooLarge,

    #[error("DNS response carried inconsistent validation states for one TXT RRset")]
    InconsistentDnssec,
}

pub type Result<T> = std::result::Result<T, DomainVerificationError>;

/// Verify a portable proof and make one bounded, DNSSEC-validating TXT lookup
/// using the operating system's configured recursive resolver.
///
/// Network failures return an error rather than being confused with a missing
/// publication. Authenticated and unauthenticated negative answers are normal
/// evidence reports with `domain_control` set to `not_established`.
pub async fn verify_domain_control_live(
    proof: &ProofBundle,
    now: i64,
) -> Result<LiveDomainControlVerification> {
    let portable = verify_domain_control_proof(proof, now)?;
    let query_name = Name::from_ascii(&portable.dns_record_name)
        .map_err(|_| DomainVerificationError::InvalidQueryName)?;
    let resolver = validating_system_resolver()?;

    let lookup = tokio::time::timeout(
        DNS_LOOKUP_DEADLINE,
        resolver.lookup(query_name.clone(), RecordType::TXT),
    )
    .await
    .map_err(|_| DomainVerificationError::LookupTimedOut)?;

    match lookup {
        Ok(lookup) => evaluate_records(portable, now, &query_name, lookup.answers(), None),
        Err(error) => {
            if matches!(error, NetError::Timeout) {
                return Err(DomainVerificationError::LookupTimedOut);
            }
            if let Some(dnssec) = negative_dnssec_status(&error) {
                return evaluate_records(portable, now, &query_name, &[], Some(dnssec));
            }
            Err(DomainVerificationError::LookupFailed)
        }
    }
}

fn validating_system_resolver() -> Result<hickory_resolver::TokioResolver> {
    let mut builder =
        Resolver::builder_tokio().map_err(|_| DomainVerificationError::ResolverConfiguration)?;
    harden_resolver_options(builder.options_mut());
    builder
        .build()
        .map_err(|_| DomainVerificationError::ResolverInitialization)
}

fn harden_resolver_options(options: &mut ResolverOpts) {
    // Hickory's default is false even when its DNSSEC feature is compiled in.
    options.validate = true;
    options.timeout = DNS_REQUEST_TIMEOUT;
    options.attempts = 2;
    options.cache_size = 32;
    options.use_hosts_file = ResolveHosts::Never;
    options.positive_max_ttl = Some(DNS_CACHE_TTL_CAP);
    options.negative_max_ttl = Some(DNS_CACHE_TTL_CAP);
    options.num_concurrent_reqs = 1;
    options.max_active_requests = 1;
    options.preserve_intermediates = true;
    options.try_tcp_on_error = true;
    options.case_randomization = true;
}

fn evaluate_records(
    portable: DomainControlVerification,
    checked_at: i64,
    expected_name: &Name,
    answers: &[Record],
    negative_dnssec: Option<DnssecStatus>,
) -> Result<LiveDomainControlVerification> {
    if answers.len() > MAX_ANSWER_RECORDS {
        return Err(DomainVerificationError::ResponseTooLarge);
    }

    let expected_value = portable.dns_txt_value.as_bytes();
    let mut total_txt_bytes = 0_usize;
    let mut rrset_dnssec = None;
    let mut publication = PublicationStatus::Missing;
    let mut matching_ttl = None;

    for record in answers {
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        let record_bytes = txt
            .txt_data
            .iter()
            .try_fold(0_usize, |total, part| total.checked_add(part.len()));
        let Some(record_bytes) = record_bytes else {
            return Err(DomainVerificationError::ResponseTooLarge);
        };
        if record_bytes > MAX_TXT_RECORD_BYTES {
            return Err(DomainVerificationError::ResponseTooLarge);
        }
        total_txt_bytes = total_txt_bytes
            .checked_add(record_bytes)
            .ok_or(DomainVerificationError::ResponseTooLarge)?;
        if total_txt_bytes > MAX_TOTAL_TXT_BYTES {
            return Err(DomainVerificationError::ResponseTooLarge);
        }

        // Hickory's Name equality is case-insensitive but FQDN-aware. A TXT
        // reached only after following a CNAME therefore cannot satisfy this.
        if &record.name != expected_name {
            continue;
        }

        let record_dnssec = map_hickory_proof(record.proof);
        match rrset_dnssec {
            Some(existing) if existing != record_dnssec => {
                return Err(DomainVerificationError::InconsistentDnssec);
            }
            None => rrset_dnssec = Some(record_dnssec),
            _ => {}
        }

        let exact_match = record_bytes == expected_value.len()
            && txt
                .txt_data
                .iter()
                .flat_map(|part| part.iter().copied())
                .eq(expected_value.iter().copied());
        if exact_match {
            publication = PublicationStatus::Matched;
            matching_ttl =
                Some(matching_ttl.map_or(record.ttl, |current: u32| current.min(record.ttl)));
        }
    }

    let dnssec = rrset_dnssec
        .or(negative_dnssec)
        .unwrap_or(DnssecStatus::Indeterminate);
    Ok(build_report(
        portable,
        checked_at,
        publication,
        dnssec,
        matching_ttl,
    ))
}

fn build_report(
    portable: DomainControlVerification,
    checked_at: i64,
    publication: PublicationStatus,
    dnssec: DnssecStatus,
    matching_record_ttl_seconds: Option<u32>,
) -> LiveDomainControlVerification {
    let domain_control = match (publication, dnssec) {
        (PublicationStatus::Matched, DnssecStatus::Secure) => DomainControlStatus::VerifiedDnssec,
        (PublicationStatus::Matched, DnssecStatus::Insecure) => {
            DomainControlStatus::ObservedUnsigned
        }
        _ => DomainControlStatus::NotEstablished,
    };

    let mut not_established = portable.not_established;
    if publication == PublicationStatus::Matched {
        not_established.retain(|claim| claim != "dns_publication");
    }
    match domain_control {
        DomainControlStatus::VerifiedDnssec => {}
        DomainControlStatus::ObservedUnsigned => {
            not_established.push("dnssec_authenticated_domain_control".to_owned());
        }
        DomainControlStatus::NotEstablished => {
            not_established.push("current_domain_control".to_owned());
        }
    }

    LiveDomainControlVerification {
        signature: portable.signature,
        validity: portable.validity,
        publication,
        dnssec,
        domain_control,
        domain: portable.domain,
        dns_record_name: portable.dns_record_name,
        dns_txt_value: portable.dns_txt_value,
        issued_at: portable.issued_at,
        expires_at: portable.expires_at,
        checked_at,
        matching_record_ttl_seconds,
        signer: portable.signer,
        not_established,
    }
}

fn negative_dnssec_status(error: &NetError) -> Option<DnssecStatus> {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            Some(no_records_dnssec_status(no_records))
        }
        NetError::Dns(DnsError::Nsec { proof, .. }) => Some(map_hickory_proof(*proof)),
        _ => None,
    }
}

fn no_records_dnssec_status(no_records: &NoRecords) -> DnssecStatus {
    let mut status = None;
    let mut has_secure_denial = false;
    if let Some(authorities) = &no_records.authorities {
        for record in authorities.iter() {
            let proof = map_hickory_proof(record.proof);
            has_secure_denial |= proof == DnssecStatus::Secure
                && matches!(
                    record.data.record_type(),
                    RecordType::NSEC | RecordType::NSEC3
                );
            status = Some(match (status, proof) {
                (Some(DnssecStatus::Bogus), _) | (_, DnssecStatus::Bogus) => DnssecStatus::Bogus,
                (Some(DnssecStatus::Indeterminate), _) | (_, DnssecStatus::Indeterminate) => {
                    DnssecStatus::Indeterminate
                }
                (Some(DnssecStatus::Insecure), _) | (_, DnssecStatus::Insecure) => {
                    DnssecStatus::Insecure
                }
                _ => DnssecStatus::Secure,
            });
        }
    }
    match status {
        Some(DnssecStatus::Secure) if has_secure_denial => DnssecStatus::Secure,
        Some(DnssecStatus::Secure) | None => DnssecStatus::Indeterminate,
        Some(other) => other,
    }
}

fn map_hickory_proof(proof: HickoryProof) -> DnssecStatus {
    match proof {
        HickoryProof::Secure => DnssecStatus::Secure,
        HickoryProof::Insecure => DnssecStatus::Insecure,
        HickoryProof::Bogus => DnssecStatus::Bogus,
        HickoryProof::Indeterminate => DnssecStatus::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{Query, ResponseCode};
    use hickory_resolver::proto::rr::rdata::TXT;

    use super::*;

    const EXPECTED: &str = "a-quo-domain-v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn portable() -> DomainControlVerification {
        DomainControlVerification {
            signature: EvidenceStatus::Verified,
            validity: EvidenceStatus::Verified,
            domain: "a-quo.ch".to_owned(),
            dns_record_name: "a-quo.ch.".to_owned(),
            dns_txt_value: EXPECTED.to_owned(),
            issued_at: 1_787_875_200,
            expires_at: 1_788_480_000,
            signer: VerifiedSigner {
                persona: "A Quo publisher".to_owned(),
                key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                identity_binding: "self_asserted".to_owned(),
            },
            not_established: vec![
                "dns_publication".to_owned(),
                "legal_domain_ownership".to_owned(),
                "trusted_timestamp".to_owned(),
            ],
        }
    }

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }

    fn txt_record(owner: &str, parts: Vec<&[u8]>, ttl: u32, proof: HickoryProof) -> Record {
        let mut record = Record::from_rdata(name(owner), ttl, RData::TXT(TXT::from_bytes(parts)));
        record.proof = proof;
        record
    }

    fn evaluate(answers: &[Record]) -> Result<LiveDomainControlVerification> {
        evaluate_records(portable(), 1_787_875_300, &name("a-quo.ch."), answers, None)
    }

    #[test]
    fn secure_exact_match_establishes_only_current_dnssec_control() {
        let record = txt_record(
            "A-QUO.CH.",
            vec![EXPECTED.as_bytes()],
            600,
            HickoryProof::Secure,
        );
        let report = evaluate(&[record]).unwrap();

        assert_eq!(report.publication, PublicationStatus::Matched);
        assert_eq!(report.dnssec, DnssecStatus::Secure);
        assert_eq!(report.domain_control, DomainControlStatus::VerifiedDnssec);
        assert_eq!(report.matching_record_ttl_seconds, Some(600));
        assert!(
            !report
                .not_established
                .contains(&"dns_publication".to_owned())
        );
        assert!(
            report
                .not_established
                .contains(&"legal_domain_ownership".to_owned())
        );
    }

    #[test]
    fn split_unsigned_txt_is_observed_but_not_authenticated() {
        let split = 24;
        let record = txt_record(
            "a-quo.ch.",
            vec![&EXPECTED.as_bytes()[..split], &EXPECTED.as_bytes()[split..]],
            120,
            HickoryProof::Insecure,
        );
        let report = evaluate(&[record]).unwrap();

        assert_eq!(report.publication, PublicationStatus::Matched);
        assert_eq!(report.dnssec, DnssecStatus::Insecure);
        assert_eq!(report.domain_control, DomainControlStatus::ObservedUnsigned);
        assert!(
            report
                .not_established
                .contains(&"dnssec_authenticated_domain_control".to_owned())
        );
    }

    #[test]
    fn cname_target_substrings_and_case_changes_do_not_match() {
        let target = txt_record(
            "hosting.example.net.",
            vec![EXPECTED.as_bytes()],
            300,
            HickoryProof::Secure,
        );
        let substring = format!("prefix-{EXPECTED}");
        let wrong_case = EXPECTED.to_ascii_uppercase();
        let same_owner_substring = txt_record(
            "a-quo.ch.",
            vec![substring.as_bytes()],
            300,
            HickoryProof::Secure,
        );
        let same_owner_wrong_case = txt_record(
            "a-quo.ch.",
            vec![wrong_case.as_bytes()],
            300,
            HickoryProof::Secure,
        );
        let report = evaluate(&[target, same_owner_substring, same_owner_wrong_case]).unwrap();

        assert_eq!(report.publication, PublicationStatus::Missing);
        assert_eq!(report.dnssec, DnssecStatus::Secure);
        assert_eq!(report.domain_control, DomainControlStatus::NotEstablished);
        assert_eq!(report.matching_record_ttl_seconds, None);
    }

    #[test]
    fn bogus_or_indeterminate_match_never_establishes_control() {
        for proof in [HickoryProof::Bogus, HickoryProof::Indeterminate] {
            let record = txt_record("a-quo.ch.", vec![EXPECTED.as_bytes()], 60, proof);
            let report = evaluate(&[record]).unwrap();
            assert_eq!(report.publication, PublicationStatus::Matched);
            assert_eq!(report.domain_control, DomainControlStatus::NotEstablished);
        }
    }

    #[test]
    fn inconsistent_rrset_proofs_fail_closed() {
        let secure = txt_record(
            "a-quo.ch.",
            vec![EXPECTED.as_bytes()],
            60,
            HickoryProof::Secure,
        );
        let insecure = txt_record("a-quo.ch.", vec![b"unrelated"], 60, HickoryProof::Insecure);
        assert!(matches!(
            evaluate(&[secure, insecure]),
            Err(DomainVerificationError::InconsistentDnssec)
        ));
    }

    #[test]
    fn processing_bounds_are_enforced() {
        let records = (0..=MAX_ANSWER_RECORDS)
            .map(|_| txt_record("a-quo.ch.", vec![b"unrelated"], 60, HickoryProof::Secure))
            .collect::<Vec<_>>();
        assert!(matches!(
            evaluate(&records),
            Err(DomainVerificationError::ResponseTooLarge)
        ));

        let oversized = vec![b'x'; MAX_TXT_RECORD_BYTES + 1];
        let record = txt_record(
            "a-quo.ch.",
            vec![oversized.as_slice()],
            60,
            HickoryProof::Secure,
        );
        assert!(matches!(
            evaluate(&[record]),
            Err(DomainVerificationError::ResponseTooLarge)
        ));
    }

    #[test]
    fn authenticated_negative_answer_is_missing_not_a_lookup_failure() {
        let report = evaluate_records(
            portable(),
            1_787_875_300,
            &name("a-quo.ch."),
            &[],
            Some(DnssecStatus::Secure),
        )
        .unwrap();
        assert_eq!(report.publication, PublicationStatus::Missing);
        assert_eq!(report.dnssec, DnssecStatus::Secure);
        assert_eq!(report.domain_control, DomainControlStatus::NotEstablished);
        assert!(
            report
                .not_established
                .contains(&"dns_publication".to_owned())
        );
    }

    #[test]
    fn resolver_is_explicitly_validating_and_bounded() {
        let mut options = ResolverOpts::default();
        harden_resolver_options(&mut options);

        assert!(options.validate);
        assert_eq!(options.timeout, DNS_REQUEST_TIMEOUT);
        assert_eq!(options.attempts, 2);
        assert_eq!(options.cache_size, 32);
        assert_eq!(options.use_hosts_file, ResolveHosts::Never);
        assert_eq!(options.positive_max_ttl, Some(DNS_CACHE_TTL_CAP));
        assert_eq!(options.negative_max_ttl, Some(DNS_CACHE_TTL_CAP));
        assert_eq!(options.num_concurrent_reqs, 1);
        assert_eq!(options.max_active_requests, 1);
        assert!(options.preserve_intermediates);
        assert!(options.try_tcp_on_error);
        assert!(options.case_randomization);
    }

    #[test]
    fn negative_status_requires_an_authenticated_denial_rrset() {
        let mut no_records = NoRecords::new(
            Query::query(name("a-quo.ch."), RecordType::TXT),
            ResponseCode::NoError,
        );
        assert_eq!(
            no_records_dnssec_status(&no_records),
            DnssecStatus::Indeterminate
        );

        let mut signed_soa = Record::update0(name("a-quo.ch."), 60, RecordType::SOA);
        signed_soa.proof = HickoryProof::Secure;
        no_records.authorities = Some(Arc::from([signed_soa]));
        assert_eq!(
            no_records_dnssec_status(&no_records),
            DnssecStatus::Indeterminate
        );

        let mut signed_nsec = Record::update0(name("a-quo.ch."), 60, RecordType::NSEC);
        signed_nsec.proof = HickoryProof::Secure;
        no_records.authorities = Some(Arc::from([signed_nsec]));
        assert_eq!(no_records_dnssec_status(&no_records), DnssecStatus::Secure);
    }
}
