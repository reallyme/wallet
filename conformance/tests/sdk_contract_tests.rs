// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK consumption contract tests.

use reallyme_wallet::proto_codec::decode::decode_credential_record;
use reallyme_wallet::proto_codec::encode::encode_credential_record;
use reallyme_wallet::proto_codec::ProtoError;
use reallyme_wallet::types as wallet;
use thiserror::Error;

const SDK_BOUNDARY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/wallets/wallet-core-sdk-boundary.json"
));

#[derive(Debug, Error)]
enum SdkContractTestError {
    #[error("proto")]
    Proto(#[from] ProtoError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("fixture_json")]
    FixtureJson,
    #[error("fixture_contract")]
    FixtureContract,
}

#[test]
fn sdk_boundary_fixture_names_only_the_canonical_operation_protocol(
) -> Result<(), SdkContractTestError> {
    let fixture: serde_json::Value = serde_json::from_str(SDK_BOUNDARY_FIXTURE)
        .map_err(|_| SdkContractTestError::FixtureJson)?;
    if fixture
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || fixture.get("compatibility_service").is_some()
        || fixture
            .get("canonical_service")
            .and_then(serde_json::Value::as_str)
            != Some("reallyme.wallet.v1.WalletCoreService")
        || fixture
            .get("canonical_method")
            .and_then(serde_json::Value::as_str)
            != Some("WalletOperation")
        || fixture
            .get("operation_golden_fixture")
            .and_then(serde_json::Value::as_str)
            != Some("vectors/wallet-operation-v1-golden.json")
        || fixture
            .get("provider_golden_fixture")
            .and_then(serde_json::Value::as_str)
            != Some("vectors/wallet-provider-v1-golden.txt")
    {
        return Err(SdkContractTestError::FixtureContract);
    }
    Ok(())
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(1)
}

fn encrypted_record() -> Result<wallet::EncryptedRecord, wallet::WalletTypesError> {
    Ok(wallet::EncryptedRecord {
        header: wallet::EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
            algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp()?,
        },
        nonce: vec![1; 12],
        aad: vec![4, 5, 6],
        ciphertext: vec![7; 16],
    })
}

#[test]
fn identity_can_use_facade_proto_bytes_without_lower_layer_artifacts(
) -> Result<(), SdkContractTestError> {
    let record = wallet::CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        None,
        Some(wallet::KeyHandleId::new("holder-key-1".to_owned())?),
        None,
        wallet::CredentialFormat::SdJwtVc,
        wallet::CredentialStatus::Active,
        timestamp()?,
        encrypted_record()?,
    );

    let bytes = encode_credential_record(&record)?;
    let decoded = decode_credential_record(&bytes);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}
