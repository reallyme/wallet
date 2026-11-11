// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::ZeroizeOnDrop;

use super::{
    CredentialFormat, CredentialMutationErrorReason, CredentialRecord, CredentialStatus,
    CredentialStatusEvidence, CredentialStatusEvidenceMethod, CredentialStatusReference,
    OnceOnlyPresentationCopy,
};
use crate::{
    EncryptedRecord, EncryptedRecordHeader, KeyHandleId, NonEmptyIdentifier,
    SignedCredentialIssuer, StorageEncryptionAlgorithm, UnixTimestamp, WalletTypesError,
};

#[test]
fn credential_owners_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<CredentialRecord>();
    assert_zeroize_on_drop::<CredentialStatusEvidence>();
    assert_zeroize_on_drop::<OnceOnlyPresentationCopy>();
}

#[test]
fn status_debug_does_not_expose_list_coordinates() -> Result<(), WalletTypesError> {
    let issuer = SignedCredentialIssuer::new("issuer.example".to_owned())?;
    let reference = CredentialStatusReference::new(issuer.clone(), [0xAB; 32], 4242, None);
    let at = UnixTimestamp::from_seconds(1)?;
    let evidence = CredentialStatusEvidence {
        credential_id: NonEmptyIdentifier::new("credential-1".to_owned())?,
        observed_status: CredentialStatus::Active,
        method: CredentialStatusEvidenceMethod::TokenStatusList,
        source_issuer: issuer,
        source_list_id: [0xAB; 32],
        status_index: 4242,
        source_issued_at: at,
        checked_at: at,
        valid_until: at,
    };

    assert_eq!(
        format!("{reference:?}"),
        "CredentialStatusReference(<redacted>)"
    );
    assert_eq!(
        format!("{evidence:?}"),
        "CredentialStatusEvidence(<redacted>)"
    );
    Ok(())
}

#[test]
fn status_commit_rejects_a_source_dated_after_trusted_now() -> Result<(), WalletTypesError> {
    let issuer = SignedCredentialIssuer::new("issuer.example".to_owned())?;
    let mut record = CredentialRecord::new(
        NonEmptyIdentifier::new("credential-1".to_owned())?,
        NonEmptyIdentifier::new("issuer-1".to_owned())?,
        None,
        None,
        Some(CredentialStatusReference::new(issuer, [9; 32], 0, None)),
        CredentialFormat::SdJwtVc,
        CredentialStatus::Active,
        UnixTimestamp::from_seconds(10)?,
        EncryptedRecord {
            header: EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: KeyHandleId::new("key-1".to_owned())?,
                algorithm: StorageEncryptionAlgorithm::Aes256GcmSiv,
                created_at: UnixTimestamp::from_seconds(1)?,
            },
            nonce: vec![1; 12],
            aad: vec![2],
            ciphertext: vec![3; 16],
        },
    );

    let result = record.commit_authenticated_status(
        CredentialStatus::Active,
        UnixTimestamp::from_seconds(4_102_444_800)?,
        UnixTimestamp::from_seconds(20)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == CredentialMutationErrorReason::FutureStatusSource
    ));
    assert_eq!(
        record
            .status_reference()
            .and_then(CredentialStatusReference::last_source_issued_at),
        None
    );
    Ok(())
}
