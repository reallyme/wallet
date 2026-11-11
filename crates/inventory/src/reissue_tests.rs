// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialStatus, CredentialStatusEvidence,
    CredentialStatusEvidenceMethod, CredentialStatusReference, EncryptedRecord,
    EncryptedRecordHeader, NonEmptyIdentifier, SignedCredentialIssuer, UnixTimestamp,
    WalletTypesError,
};

use super::reissue_credential_record;
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

fn record(
    credential_id: &str,
    issuer_id: &str,
    status: CredentialStatus,
) -> Result<CredentialRecord, WalletTypesError> {
    Ok(CredentialRecord::new(
        id(credential_id)?,
        id(issuer_id)?,
        Some(SignedCredentialIssuer::new(issuer_id.to_owned())?),
        None,
        Some(CredentialStatusReference::new(
            SignedCredentialIssuer::new(issuer_id.to_owned())?,
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

fn evidence() -> Result<CredentialStatusEvidence, WalletTypesError> {
    Ok(CredentialStatusEvidence {
        credential_id: id("credential-1")?,
        observed_status: CredentialStatus::Active,
        method: CredentialStatusEvidenceMethod::IssuerRefresh,
        source_issuer: SignedCredentialIssuer::new("issuer-1".to_owned())?,
        source_list_id: [9; 32],
        status_index: 0,
        source_issued_at: timestamp(9)?,
        checked_at: timestamp(10)?,
        valid_until: timestamp(20)?,
    })
}

#[test]
fn reissues_to_same_issuer_replacement() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let replacement = record("credential-2", "issuer-1", CredentialStatus::Active)?;

    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);

    assert!(matches!(
        result,
        Ok(record) if record.id.as_str() == "credential-2"
    ));
    assert_eq!(current.status(), CredentialStatus::Deleted);
    Ok(())
}

#[test]
fn rejects_cross_issuer_replacement() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let replacement = record("credential-2", "issuer-2", CredentialStatus::Active)?;

    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::IssuerMismatch
    ));
    assert_eq!(current.status(), CredentialStatus::Active);
    Ok(())
}

#[test]
fn rejects_non_active_replacement() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let replacement = record("credential-2", "issuer-1", CredentialStatus::Suspended)?;

    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidImportStatus
    ));
    assert_eq!(current.status(), CredentialStatus::Active);
    Ok(())
}

#[test]
fn rejects_replacement_that_reuses_the_retired_record_id() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let original = current.clone();
    let replacement = record("credential-1", "issuer-1", CredentialStatus::Active)?;

    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidRefreshEvidence
    ));
    assert!(current == original);
    Ok(())
}

#[test]
fn reissue_cannot_reactivate_a_suspended_credential() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Suspended)?;
    let replacement = record("credential-2", "issuer-1", CredentialStatus::Active)?;

    // Even active evidence cannot lift the suspension through reissuance; the
    // evidence check itself is covered by the next test.
    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidRefreshEvidence
    ));
    assert_eq!(current.status(), CredentialStatus::Suspended);
    Ok(())
}

#[test]
fn reissue_rejects_evidence_that_is_not_active() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let replacement = record("credential-2", "issuer-1", CredentialStatus::Active)?;
    let mut suspended_evidence = evidence()?;
    suspended_evidence.observed_status = CredentialStatus::Suspended;

    let result = reissue_credential_record(
        &mut current,
        replacement,
        &suspended_evidence,
        timestamp(15)?,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidRefreshEvidence
    ));
    assert_eq!(current.status(), CredentialStatus::Active);
    Ok(())
}

#[test]
fn reissue_rejects_a_replacement_with_another_issuer_id() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let mut replacement = record("credential-2", "issuer-1", CredentialStatus::Active)?;
    replacement.issuer_id = id("issuer-2")?;

    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::IssuerMismatch
    ));
    assert_eq!(current.status(), CredentialStatus::Active);
    Ok(())
}

#[test]
fn reissue_rejects_a_replacement_without_status_coverage() -> Result<(), WalletTypesError> {
    let mut current = record("credential-1", "issuer-1", CredentialStatus::Active)?;
    let template = record("credential-2", "issuer-1", CredentialStatus::Active)?;
    let replacement = CredentialRecord::new(
        template.id.clone(),
        template.issuer_id.clone(),
        template.signed_issuer.clone(),
        None,
        None,
        CredentialFormat::SdJwtVc,
        CredentialStatus::Active,
        timestamp(1)?,
        encrypted()?,
    );

    let result = reissue_credential_record(&mut current, replacement, &evidence()?, timestamp(15)?);
    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::InvalidRefreshEvidence
    ));
    assert_eq!(current.status(), CredentialStatus::Active);
    Ok(())
}
