// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent canonical v2 transcript vector and v1 migration boundaries.
#![cfg(feature = "native")]
use reallyme_wallet::{
    log::{chain_history_record, validate_history_record, HistoryError},
    types::{
        AttributeName, CredentialRecordId, HistoryFailureReason, HistoryOutcome, HistoryPurpose,
        NonEmptyIdentifier, RelyingPartyId, TransactionHistoryRecord, TransactionLogEntryId,
        UnixTimestamp, WalletTypesError,
    },
};
use thiserror::Error;
#[test]
fn v2_transcript_matches_independent_vector_and_rejects_every_hash_bit_change(
) -> Result<(), TestError> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/transaction-history-v2.json"))
            .map_err(|_| TestError::Fixture)?;
    let entry = TransactionHistoryRecord {
        id: TransactionLogEntryId::new("history-1".into())?,
        purpose: HistoryPurpose::Presentation,
        outcome: HistoryOutcome::Completed,
        reason: HistoryFailureReason::None,
        relying_party_id: Some(RelyingPartyId::new("https://reader.example".into())?),
        requested: vec![AttributeName::new("age".into())?],
        presented: vec![AttributeName::new("age".into())?],
        credential_ids: vec![CredentialRecordId::new("credential-1".into())?],
        consent_digest: Some([4; 32]),
        operation_id: NonEmptyIdentifier::new("operation-1".into())?,
        occurred_at: UnixTimestamp::from_seconds(20)?,
        sequence: 0,
        previous_hash: [0; 32],
        entry_hash: [0; 32],
    };
    let entry = chain_history_record(entry, (0, [0; 32]))?;
    let expected = fixture["entry_hash_hex"]
        .as_str()
        .ok_or(TestError::Fixture)?;
    let actual = entry
        .entry_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(actual, expected);
    for index in 0..32 {
        for bit in 0..8 {
            let mut tampered = entry.clone();
            tampered.entry_hash[index] ^= 1_u8 << bit;
            assert!(validate_history_record(&tampered).is_err());
        }
    }
    let proto =
        reallyme_wallet::proto_codec::policy_records::encode_transaction_history_record(&entry)
            .map_err(|_| TestError::Fixture)?;
    let decoded =
        reallyme_wallet::proto_codec::policy_records::decode_transaction_history_record(&proto)
            .map_err(|_| TestError::Fixture)?;
    validate_history_record(&decoded)?;
    assert!(decoded == entry);
    Ok(())
}
#[derive(Debug, Error)]
enum TestError {
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("history")]
    History(#[from] HistoryError),
    #[error("fixture")]
    Fixture,
}
