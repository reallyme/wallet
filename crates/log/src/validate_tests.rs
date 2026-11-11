// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    AttributeName, DecisionOutcome, DisclosedAttribute, QtspDecisionKind, QtspDecisionRecord,
    TransactionLogEntry, TransactionPurpose, UnixTimestamp, WalletTypesError,
};

use super::{
    chain_transaction_log_entry, validate_qtsp_decision_record, validate_transaction_log_chain,
    validate_transaction_log_chain_to_head, validate_transaction_log_entry,
};
use crate::{WalletLogError, WalletLogErrorReason};

#[derive(Debug)]
enum TestError {
    Types,
    Log,
}

impl From<WalletTypesError> for TestError {
    fn from(_error: WalletTypesError) -> Self {
        Self::Types
    }
}

impl From<WalletLogError> for TestError {
    fn from(_error: WalletLogError) -> Self {
        Self::Log
    }
}

fn timestamp() -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(1)
}

#[test]
fn rejects_presentation_without_relying_party() -> Result<(), WalletTypesError> {
    let entry = TransactionLogEntry {
        id: reallyme_wallet_types::TransactionLogEntryId::new("log-1".to_owned())?,
        purpose: TransactionPurpose::Presentation,
        relying_party_id: None,
        disclosed_attributes: Vec::new(),
        occurred_at: timestamp()?,
        sequence: 0,
        previous_entry_hash: [0; 32],
        entry_hash: [0; 32],
    };

    let result = validate_transaction_log_entry(&entry);

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletLogErrorReason::MissingRelyingParty
    ));
    Ok(())
}

#[test]
fn rejects_decision_without_digest() -> Result<(), WalletTypesError> {
    let record = QtspDecisionRecord {
        kind: QtspDecisionKind::CredentialStatus,
        outcome: DecisionOutcome::Reject,
        input_sha256_b64url: String::new(),
        decided_at: timestamp()?,
    };

    let result = validate_qtsp_decision_record(&record);

    assert!(matches!(
        result,
        Err(error) if error.reason == WalletLogErrorReason::MissingDecisionDigest
    ));
    Ok(())
}

#[test]
fn accepts_only_canonical_sha256_decision_digests() -> Result<(), WalletTypesError> {
    let mut record = QtspDecisionRecord {
        kind: QtspDecisionKind::CredentialStatus,
        outcome: DecisionOutcome::Reject,
        input_sha256_b64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        decided_at: timestamp()?,
    };
    assert!(validate_qtsp_decision_record(&record).is_ok());

    for invalid in ["x".to_owned(), "AA=".to_owned(), "_".repeat(43)] {
        record.input_sha256_b64url = invalid;
        assert!(matches!(
            validate_qtsp_decision_record(&record),
            Err(error) if error.reason == WalletLogErrorReason::InvalidDecisionDigest
        ));
    }
    record.input_sha256_b64url = "A".repeat(44);
    assert!(matches!(
        validate_qtsp_decision_record(&record),
        Err(error) if error.reason == WalletLogErrorReason::DecisionDigestTooLong
    ));
    Ok(())
}

fn unchained_entry(id: &str) -> Result<TransactionLogEntry, WalletTypesError> {
    Ok(TransactionLogEntry {
        id: reallyme_wallet_types::TransactionLogEntryId::new(id.to_owned())?,
        purpose: TransactionPurpose::Issuance,
        relying_party_id: None,
        disclosed_attributes: Vec::new(),
        occurred_at: timestamp()?,
        sequence: 0,
        previous_entry_hash: [0; 32],
        entry_hash: [0; 32],
    })
}

#[test]
fn validates_ordered_hash_chain() -> Result<(), TestError> {
    let first = chain_transaction_log_entry(unchained_entry("log-1")?, 1, [0; 32])?;
    let second = chain_transaction_log_entry(unchained_entry("log-2")?, 2, first.entry_hash)?;

    assert!(validate_transaction_log_chain(&[first, second]).is_ok());
    Ok(())
}

#[test]
fn rejects_tampered_or_reordered_hash_chain() -> Result<(), TestError> {
    let first = chain_transaction_log_entry(unchained_entry("log-1")?, 1, [0; 32])?;
    let mut second = chain_transaction_log_entry(unchained_entry("log-2")?, 2, first.entry_hash)?;
    second.occurred_at = UnixTimestamp::from_seconds(2)?;

    assert!(matches!(
        validate_transaction_log_chain(&[first.clone(), second]),
        Err(error) if error.reason == WalletLogErrorReason::InvalidTransactionChain
    ));
    assert!(matches!(
        validate_transaction_log_chain(&[first.clone(), first]),
        Err(error) if error.reason == WalletLogErrorReason::InvalidTransactionChain
    ));
    Ok(())
}

#[test]
fn hashes_multiple_sensitive_attributes_without_transcript_growth() -> Result<(), TestError> {
    let mut entry = unchained_entry("log-multiple-attributes")?;
    entry.purpose = TransactionPurpose::Presentation;
    entry.relying_party_id = Some(reallyme_wallet_types::RelyingPartyId::new(
        "rp-1".to_owned(),
    )?);
    entry.disclosed_attributes = vec![
        DisclosedAttribute {
            name: AttributeName::new("given_name".to_owned())?,
        },
        DisclosedAttribute {
            name: AttributeName::new("family_name".to_owned())?,
        },
    ];

    let chained = chain_transaction_log_entry(entry, 1, [0; 32])?;
    assert!(validate_transaction_log_chain(&[chained]).is_ok());
    Ok(())
}

#[test]
fn anchored_chain_detects_a_dropped_tail() -> Result<(), TestError> {
    let first = chain_transaction_log_entry(unchained_entry("log-1")?, 1, [0; 32])?;
    let second = chain_transaction_log_entry(unchained_entry("log-2")?, 2, first.entry_hash)?;
    let head = (second.sequence, second.entry_hash);

    assert!(validate_transaction_log_chain_to_head(&[first.clone(), second], head).is_ok());
    assert!(matches!(
        validate_transaction_log_chain_to_head(&[first], head),
        Err(error) if error.reason == WalletLogErrorReason::InvalidTransactionChain
    ));
    assert!(matches!(
        validate_transaction_log_chain_to_head(&[], head),
        Err(error) if error.reason == WalletLogErrorReason::InvalidTransactionChain
    ));
    assert!(validate_transaction_log_chain_to_head(&[], (0, [0; 32])).is_ok());
    Ok(())
}

#[test]
fn chain_rejects_duplicate_identifiers() -> Result<(), TestError> {
    let first = chain_transaction_log_entry(unchained_entry("log-1")?, 1, [0; 32])?;
    let duplicate = chain_transaction_log_entry(unchained_entry("log-1")?, 2, first.entry_hash)?;
    assert!(matches!(
        validate_transaction_log_chain(&[first, duplicate]),
        Err(error) if error.reason == WalletLogErrorReason::InvalidTransactionChain
    ));
    Ok(())
}

#[test]
fn chain_accepts_entries_logged_out_of_event_order() -> Result<(), TestError> {
    let mut later = unchained_entry("log-1")?;
    later.occurred_at = UnixTimestamp::from_seconds(20)?;
    let first = chain_transaction_log_entry(later, 1, [0; 32])?;
    let mut earlier = unchained_entry("log-2")?;
    earlier.occurred_at = UnixTimestamp::from_seconds(10)?;
    let second = chain_transaction_log_entry(earlier, 2, first.entry_hash)?;
    // A presentation that finished before an issuance may be logged after it.
    assert!(validate_transaction_log_chain(&[first, second]).is_ok());
    Ok(())
}

#[test]
fn entry_rejects_more_disclosed_attributes_than_the_bound() -> Result<(), TestError> {
    let mut entry = unchained_entry("log-many-attributes")?;
    entry.purpose = TransactionPurpose::Presentation;
    entry.relying_party_id = Some(reallyme_wallet_types::RelyingPartyId::new(
        "rp-1".to_owned(),
    )?);
    let attribute = DisclosedAttribute {
        name: AttributeName::new("given_name".to_owned())?,
    };
    entry.disclosed_attributes =
        vec![attribute; crate::MAX_TRANSACTION_LOG_DISCLOSED_ATTRIBUTES + 1];
    assert!(matches!(
        chain_transaction_log_entry(entry, 1, [0; 32]),
        Err(error) if error.reason == WalletLogErrorReason::TransactionTranscriptTooLarge
    ));
    Ok(())
}
