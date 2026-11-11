// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::BatchPool;
use crate::{InventoryError, InventoryErrorReason};
use reallyme_wallet_types::{
    BatchCopyState, EncryptedRecord, EncryptedRecordHeader, NonEmptyIdentifier,
    OnceOnlyPresentationCopy, UnixTimestamp, WalletTypesError,
};

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn encrypted() -> Result<EncryptedRecord, WalletTypesError> {
    let timestamp = UnixTimestamp::from_seconds(1)?;

    Ok(EncryptedRecord {
        header: EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            algorithm: reallyme_wallet_types::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp,
        },
        nonce: vec![1; 12],
        aad: vec![2],
        ciphertext: vec![3; 16],
    })
}

fn copy(value: &str) -> Result<OnceOnlyPresentationCopy, WalletTypesError> {
    Ok(OnceOnlyPresentationCopy {
        id: id(value)?,
        credential_id: id("credential-1")?,
        prepared_claim_selector_digest: None,
        state: BatchCopyState::Available,
        encrypted_payload: encrypted()?,
    })
}

#[test]
fn claims_copy_once() -> Result<(), TestError> {
    let mut pool = BatchPool::try_new(id("credential-1")?, vec![copy("copy-1")?])?;

    let credential_id = id("credential-1")?;
    let claimed = pool.claim_for(&credential_id);

    assert!(matches!(
        claimed,
        Ok(copy) if copy.state == BatchCopyState::Claimed
    ));
    assert_eq!(pool.available_count(), 0);
    Ok(())
}

#[test]
fn rejects_exhausted_pool() -> Result<(), TestError> {
    let mut pool = BatchPool::try_new(id("credential-1")?, Vec::new())?;

    let credential_id = id("credential-1")?;
    let result = pool.claim_for(&credential_id);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::BatchPoolExhausted
    ));
    Ok(())
}

#[test]
fn rejects_wrong_credential_claim() -> Result<(), TestError> {
    let mut pool = BatchPool::try_new(id("credential-1")?, vec![copy("copy-1")?])?;

    let credential_id = id("credential-2")?;
    let result = pool.claim_for(&credential_id);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::CredentialMismatch
    ));
    assert_eq!(pool.available_count(), 1);
    Ok(())
}

#[test]
fn rejects_duplicate_copy_ids() -> Result<(), TestError> {
    let result = BatchPool::try_new(id("credential-1")?, vec![copy("copy-1")?, copy("copy-1")?]);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::DuplicatePresentationCopy
    ));
    Ok(())
}

#[test]
fn reports_a_copy_for_another_credential_as_a_mismatch() -> Result<(), TestError> {
    let mut foreign = copy("copy-2")?;
    foreign.credential_id = id("credential-2")?;
    let result = BatchPool::try_new(id("credential-1")?, vec![copy("copy-1")?, foreign]);

    assert!(matches!(
        result,
        Err(error) if error.reason == InventoryErrorReason::CredentialMismatch
    ));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("inventory")]
    Inventory(#[from] InventoryError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}
