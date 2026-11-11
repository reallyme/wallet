// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialStatus, EncryptedRecord, EncryptedRecordHeader,
    NonEmptyIdentifier, StorageEncryptionAlgorithm, UnixTimestamp, WalletTypesError,
};

use super::import_validated_credential;
use crate::InventoryErrorReason;

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
fn imports_active_validated_credential() -> Result<(), WalletTypesError> {
    let result = import_validated_credential(record(CredentialStatus::Active)?);

    assert!(matches!(
        result,
        Ok(record) if record.status() == CredentialStatus::Active
    ));
    Ok(())
}

#[test]
fn rejects_non_active_import() -> Result<(), WalletTypesError> {
    let result = import_validated_credential(record(CredentialStatus::Suspended)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidImportStatus
    ));
    Ok(())
}

#[test]
fn rejects_empty_import_payload() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    record.encrypted_payload.ciphertext.clear();

    let result = import_validated_credential(record);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidEncryptedPayload
    ));
    Ok(())
}

#[test]
fn rejects_algorithm_nonce_length_mismatch() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    record.encrypted_payload.nonce = vec![1; 24];

    let result = import_validated_credential(record);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidEncryptedPayload
    ));
    Ok(())
}

#[test]
fn rejects_ciphertext_shorter_than_authentication_tag() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    record.encrypted_payload.ciphertext = vec![3; 15];

    let result = import_validated_credential(record);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidEncryptedPayload
    ));
    Ok(())
}

#[test]
fn accepts_xchacha20_poly1305_nonce_length() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    record.encrypted_payload.header.algorithm = StorageEncryptionAlgorithm::XChaCha20Poly1305;
    record.encrypted_payload.nonce = vec![1; 24];

    let result = import_validated_credential(record);

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn rejects_zero_encrypted_record_schema_version() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    record.encrypted_payload.header.schema_version = 0;

    let result = import_validated_credential(record);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidEncryptedPayload
    ));
    Ok(())
}
