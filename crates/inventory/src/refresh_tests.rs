// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialStatus, CredentialStatusEvidence,
    CredentialStatusEvidenceMethod, CredentialStatusReference, EncryptedRecord,
    EncryptedRecordHeader, NonEmptyIdentifier, SignedCredentialIssuer, UnixTimestamp,
    WalletTypesError,
};

use super::apply_verified_refresh;
use crate::InventoryErrorReason;

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn encrypted(value: u8) -> Result<EncryptedRecord, WalletTypesError> {
    Ok(EncryptedRecord {
        header: EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            algorithm: reallyme_wallet_types::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp(1)?,
        },
        nonce: vec![value; 12],
        aad: vec![2],
        ciphertext: vec![value; 16],
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
        encrypted(1)?,
    ))
}

fn evidence(
    method: CredentialStatusEvidenceMethod,
    status: CredentialStatus,
) -> Result<CredentialStatusEvidence, WalletTypesError> {
    Ok(CredentialStatusEvidence {
        credential_id: id("credential-1")?,
        observed_status: status,
        method,
        source_issuer: SignedCredentialIssuer::new("issuer-1".to_owned())?,
        source_list_id: [9; 32],
        status_index: 0,
        source_issued_at: timestamp(9)?,
        checked_at: timestamp(10)?,
        valid_until: timestamp(20)?,
    })
}

#[test]
fn refreshes_payload_with_issuer_evidence() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Suspended)?;

    let update = apply_verified_refresh(
        &mut record,
        encrypted(9)?,
        &evidence(
            CredentialStatusEvidenceMethod::IssuerRefresh,
            CredentialStatus::Active,
        )?,
        timestamp(15)?,
    );

    assert!(matches!(
        update,
        Ok(update)
            if update.changed
                && update.previous_status == CredentialStatus::Suspended
                && update.current_status == CredentialStatus::Active
    ));
    assert_eq!(record.status(), CredentialStatus::Active);
    assert_eq!(record.encrypted_payload.nonce, vec![9; 12]);
    assert_eq!(
        record
            .status_reference()
            .and_then(CredentialStatusReference::last_source_issued_at),
        Some(timestamp(9)?)
    );
    Ok(())
}

#[test]
fn rejects_non_refresh_evidence() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Active)?;

    let result = apply_verified_refresh(
        &mut record,
        encrypted(9)?,
        &evidence(
            CredentialStatusEvidenceMethod::TokenStatusList,
            CredentialStatus::Active,
        )?,
        timestamp(15)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidRefreshEvidence
    ));
    Ok(())
}

#[test]
fn rejects_revoked_refresh() -> Result<(), WalletTypesError> {
    let mut record = record(CredentialStatus::Revoked)?;

    let result = apply_verified_refresh(
        &mut record,
        encrypted(9)?,
        &evidence(
            CredentialStatusEvidenceMethod::IssuerRefresh,
            CredentialStatus::Active,
        )?,
        timestamp(15)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::CredentialRevoked
    ));
    Ok(())
}
