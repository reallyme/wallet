// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialStatus, EncryptedRecord, EncryptedRecordHeader,
    NonEmptyIdentifier, UnixTimestamp, WalletTypesError,
};

use super::delete_credential_record;

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn encrypted() -> Result<EncryptedRecord, WalletTypesError> {
    Ok(EncryptedRecord {
        header: EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            algorithm: reallyme_wallet_types::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp(1)?,
        },
        nonce: vec![1; 12],
        aad: vec![2],
        ciphertext: vec![3; 16],
    })
}

fn record(status: CredentialStatus) -> Result<CredentialRecord, WalletTypesError> {
    Ok(CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        None,
        None,
        None,
        CredentialFormat::SdJwtVc,
        status,
        timestamp(1)?,
        encrypted()?,
    ))
}

#[test]
fn marks_active_credential_deleted() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;

    let update = delete_credential_record(&mut record);

    assert!(update.changed);
    assert_eq!(update.previous_status, CredentialStatus::Active);
    assert_eq!(update.current_status, CredentialStatus::Deleted);
    assert_eq!(record.status(), CredentialStatus::Deleted);
    Ok(())
}

#[test]
fn deleting_deleted_credential_is_idempotent() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Deleted)?;

    let update = delete_credential_record(&mut record);

    assert!(!update.changed);
    assert_eq!(record.status(), CredentialStatus::Deleted);
    Ok(())
}
