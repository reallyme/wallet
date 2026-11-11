// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialStatus, CredentialStatusEvidence,
    CredentialStatusEvidenceMethod, CredentialStatusReference, EncryptedRecord,
    EncryptedRecordHeader, NonEmptyIdentifier, SignedCredentialIssuer, UnixTimestamp,
    WalletTypesError,
};

use super::apply_status_evidence;
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
        Some(CredentialStatusReference::new(
            SignedCredentialIssuer::new("issuer-1".to_owned())?,
            [9; 32],
            0,
            None,
        )),
        CredentialFormat::SdJwtVc,
        status,
        timestamp(1)?,
        encrypted()?,
    ))
}

fn evidence(status: CredentialStatus) -> Result<CredentialStatusEvidence, WalletTypesError> {
    Ok(CredentialStatusEvidence {
        credential_id: id("credential-1")?,
        observed_status: status,
        method: CredentialStatusEvidenceMethod::TokenStatusList,
        source_issuer: SignedCredentialIssuer::new("issuer-1".to_owned())?,
        source_list_id: [9; 32],
        status_index: 0,
        source_issued_at: timestamp(9)?,
        checked_at: timestamp(10)?,
        valid_until: timestamp(20)?,
    })
}

#[test]
fn applies_suspension_status() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let update = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Suspended)?,
        timestamp(15)?,
    );

    assert!(matches!(
        update,
        Ok(update)
            if update.changed
                && update.previous_status == CredentialStatus::Active
                && update.current_status == CredentialStatus::Suspended
    ));
    assert_eq!(record.status(), CredentialStatus::Suspended);
    Ok(())
}

#[test]
fn revocation_is_terminal() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Revoked)?;
    let update = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Active)?,
        timestamp(15)?,
    );

    assert!(matches!(
        update,
        Ok(update)
            if !update.changed
                && update.current_status == CredentialStatus::Revoked
    ));
    assert_eq!(record.status(), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn identical_status_source_is_an_idempotent_no_op() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let checked = evidence(CredentialStatus::Suspended)?;
    let first = apply_status_evidence(&mut record, &checked, timestamp(15)?);
    let second = apply_status_evidence(&mut record, &checked, timestamp(15)?);

    assert!(matches!(first, Ok(update) if update.changed));
    assert!(matches!(
        second,
        Ok(update)
            if !update.changed && update.current_status == CredentialStatus::Suspended
    ));
    Ok(())
}

#[test]
fn equal_time_revocation_restricts_an_active_record() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let first = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Active)?,
        timestamp(15)?,
    );
    assert!(first.is_ok());

    let second = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Revoked)?,
        timestamp(15)?,
    );
    assert!(matches!(
        second,
        Ok(update) if update.changed && update.current_status == CredentialStatus::Revoked
    ));
    assert_eq!(record.status(), CredentialStatus::Revoked);
    Ok(())
}

#[test]
fn equal_time_active_observation_cannot_reverse_suspension() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let first = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Suspended)?,
        timestamp(15)?,
    );
    assert!(matches!(first, Ok(update) if update.changed));

    let second = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Active)?,
        timestamp(15)?,
    );
    assert!(matches!(
        second,
        Err(error) if error.reason == InventoryErrorReason::InvalidStatusEvidence
    ));
    assert_eq!(record.status(), CredentialStatus::Suspended);
    Ok(())
}

#[test]
fn rejects_stale_evidence() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let result = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Active)?,
        timestamp(21)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::StaleStatusEvidence
    ));
    Ok(())
}

#[test]
fn rejects_deleted_observation() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;
    let result = apply_status_evidence(
        &mut record,
        &evidence(CredentialStatus::Deleted)?,
        timestamp(15)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidStatusEvidence
    ));
    Ok(())
}
