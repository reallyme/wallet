// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inventory status-list evidence conformance tests.

use reallyme_credential_status::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};
use reallyme_wallet::inventory::{apply_token_status_list, InventoryError, InventoryErrorReason};
use reallyme_wallet::types as wallet;

const ISSUED_AT: u64 = 10;
const CHECKED_AT: i64 = 20;
const VALID_UNTIL: i64 = 40;
const TOKEN_STATUS_LIST_LENGTH: u64 = 8;

struct AcceptVerifier;

impl StatusListVerifier for AcceptVerifier {
    fn verify_status_list(
        &self,
        _issuer: &str,
        _alg: StatusListAlgorithm,
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        Ok(())
    }
}

struct RejectVerifier;

impl StatusListVerifier for RejectVerifier {
    fn verify_status_list(
        &self,
        _issuer: &str,
        _alg: StatusListAlgorithm,
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        Err(CredentialStatusError::InvalidSignature)
    }
}

#[test]
fn eudi_inventory_accepts_authenticated_status_list() -> Result<(), TestError> {
    let mut record = record(wallet::CredentialStatus::Suspended)?;
    let list = status_list(
        StatusPurpose::Revocation,
        vec![0],
        u64::try_from(VALID_UNTIL)?,
    )?;

    let status_update = apply_token_status_list(
        &mut record,
        &list,
        0,
        timestamp(CHECKED_AT)?,
        &AcceptVerifier,
    )?;

    assert!(status_update.changed);
    assert_eq!(
        status_update.current_status,
        wallet::CredentialStatus::Active
    );
    assert_eq!(record.status(), wallet::CredentialStatus::Active);

    Ok(())
}

#[test]
fn eudi_inventory_rejects_invalid_status_list_signature() -> Result<(), TestError> {
    let mut record = record(wallet::CredentialStatus::Active)?;
    let original_payload = record.encrypted_payload.clone();
    let list = status_list(
        StatusPurpose::Revocation,
        vec![0],
        u64::try_from(VALID_UNTIL)?,
    )?;

    let result = apply_token_status_list(
        &mut record,
        &list,
        0,
        timestamp(CHECKED_AT)?,
        &RejectVerifier,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidStatusEvidence
    ));
    assert_eq!(record.status(), wallet::CredentialStatus::Active);
    assert_eq!(record.encrypted_payload.nonce, original_payload.nonce);
    assert_eq!(record.encrypted_payload.aad, original_payload.aad);
    assert_eq!(
        record.encrypted_payload.ciphertext,
        original_payload.ciphertext
    );
    Ok(())
}

fn record(status: wallet::CredentialStatus) -> Result<wallet::CredentialRecord, TestError> {
    Ok(wallet::CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        None,
        None,
        Some(wallet::CredentialStatusReference::new(
            wallet::SignedCredentialIssuer::new("issuer-1".to_owned())?,
            [9; 32],
            0,
            None,
        )),
        wallet::CredentialFormat::SdJwtVc,
        status,
        timestamp(ISSUED_AT.try_into()?)?,
        encrypted_record(1)?,
    ))
}

fn encrypted_record(seed: u8) -> Result<wallet::EncryptedRecord, TestError> {
    let second = seed.checked_add(1).ok_or(TestError::IntegerConversion)?;
    let third = seed.checked_add(2).ok_or(TestError::IntegerConversion)?;

    Ok(wallet::EncryptedRecord {
        header: wallet::EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
            algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp(ISSUED_AT.try_into()?)?,
        },
        nonce: vec![seed; 12],
        aad: vec![second],
        ciphertext: vec![seed, second, third, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    })
}

fn status_list(
    purpose: StatusPurpose,
    encoded_list: Vec<u8>,
    next_update: u64,
) -> Result<StatusList, TestError> {
    Ok(StatusList {
        issuer: "issuer-1".to_owned(),
        purpose,
        issued_at: ISSUED_AT,
        next_update,
        encoded_list,
        length: TOKEN_STATUS_LIST_LENGTH,
        list_id: Some([9; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    })
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("integer_conversion")]
    IntegerConversion,
    #[error("inventory")]
    Inventory(#[from] InventoryError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
}

impl From<std::num::TryFromIntError> for TestError {
    fn from(_error: std::num::TryFromIntError) -> Self {
        Self::IntegerConversion
    }
}
