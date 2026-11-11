// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential_status::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};
use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialStatus, CredentialStatusReference,
    EncryptedRecord, EncryptedRecordHeader, NonEmptyIdentifier, SignedCredentialIssuer,
    UnixTimestamp, WalletTypesError,
};

use super::apply_token_status_list;
use crate::InventoryErrorReason;

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
        Some(CredentialStatusReference::new(
            SignedCredentialIssuer::new("issuer-1".to_owned())?,
            [9; 32],
            0,
            None,
        )),
        CredentialFormat::SdJwtVc,
        status,
        timestamp(10)?,
        encrypted()?,
    ))
}

fn status_list(purpose: StatusPurpose, encoded_list: Vec<u8>, next_update: u64) -> StatusList {
    StatusList {
        issuer: "issuer-1".to_owned(),
        purpose,
        issued_at: 10,
        next_update,
        encoded_list,
        length: 8,
        list_id: Some([9; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    }
}

#[test]
fn applies_clear_token_status_list_as_active() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Suspended)?;
    let list = status_list(StatusPurpose::Revocation, vec![0], 30);

    let update = apply_token_status_list(&mut record, &list, 0, timestamp(20)?, &AcceptVerifier);

    assert!(matches!(
        update,
        Ok(update)
            if update.changed
                && update.current_status == CredentialStatus::Active
    ));
    assert_eq!(record.status(), CredentialStatus::Active);
    Ok(())
}

#[test]
fn applies_revoked_token_status_list_as_terminal() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let list = status_list(StatusPurpose::Revocation, vec![1], 30);

    let update = apply_token_status_list(&mut record, &list, 0, timestamp(20)?, &AcceptVerifier);

    assert!(matches!(
        update,
        Ok(update)
            if update.changed
                && update.current_status == CredentialStatus::Revoked
    ));
    assert_eq!(record.status(), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn applies_suspended_token_status_list() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let list = status_list(StatusPurpose::Suspension, vec![1], 30);

    let update = apply_token_status_list(&mut record, &list, 0, timestamp(20)?, &AcceptVerifier);

    assert!(matches!(
        update,
        Ok(update)
            if update.changed
                && update.current_status == CredentialStatus::Suspended
    ));
    assert_eq!(record.status(), CredentialStatus::Suspended);
    Ok(())
}

#[test]
fn rejects_older_signed_list_even_when_checked_later() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Suspended)?;
    let current = status_list(StatusPurpose::Suspension, vec![1], 30);
    let first = apply_token_status_list(&mut record, &current, 0, timestamp(20)?, &AcceptVerifier);
    assert!(first.is_ok());

    let mut older = status_list(StatusPurpose::Suspension, vec![0], 40);
    older.issued_at = 9;
    let replay = apply_token_status_list(&mut record, &older, 0, timestamp(25)?, &AcceptVerifier);

    assert!(matches!(
        replay,
        Err(error) if error.reason == InventoryErrorReason::InvalidStatusEvidence
    ));
    assert_eq!(record.status(), CredentialStatus::Suspended);
    Ok(())
}

#[test]
fn rejects_expired_token_status_list() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let list = status_list(StatusPurpose::Revocation, vec![0], 15);

    let result = apply_token_status_list(&mut record, &list, 0, timestamp(20)?, &AcceptVerifier);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::StaleStatusEvidence
    ));
    Ok(())
}

#[test]
fn rejects_not_yet_valid_token_status_list() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let list = status_list(StatusPurpose::Revocation, vec![0], 30);

    let result = apply_token_status_list(&mut record, &list, 0, timestamp(5)?, &AcceptVerifier);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::StaleStatusEvidence
    ));
    Ok(())
}

#[test]
fn rejects_status_list_signature_failure() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let list = status_list(StatusPurpose::Revocation, vec![0], 30);

    let result = apply_token_status_list(&mut record, &list, 0, timestamp(20)?, &RejectVerifier);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidStatusEvidence
    ));
    Ok(())
}
