// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-record protobuf conversion and migration boundary tests.

use reallyme_wallet_proto_codec::convert::{
    credential_record_from_proto, credential_record_to_proto, ConvertErrorReason,
};
use reallyme_wallet_types as wallet;

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn record() -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    let received_at = wallet::UnixTimestamp::from_seconds(1)?;
    Ok(wallet::CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        Some(wallet::SignedCredentialIssuer::new(
            "https://signed-issuer.example".to_owned(),
        )?),
        Some(wallet::KeyHandleId::new("holder-key-1".to_owned())?),
        Some(wallet::CredentialStatusReference::new(
            wallet::SignedCredentialIssuer::new("https://signed-issuer.example".to_owned())?,
            [9; 32],
            7,
            None,
        )),
        wallet::CredentialFormat::SdJwtVc,
        wallet::CredentialStatus::Active,
        received_at,
        wallet::EncryptedRecord {
            header: wallet::EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: wallet::KeyHandleId::new("key-1".to_owned())?,
                algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
                created_at: received_at,
            },
            nonce: vec![1; 12],
            aad: vec![4, 5, 6],
            ciphertext: vec![7; 16],
        },
    ))
}

#[test]
fn credential_record_round_trips_through_proto_conversion() -> Result<(), wallet::WalletTypesError>
{
    let record = record()?;
    let proto = credential_record_to_proto(&record);
    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn zk_credential_record_retains_format_and_holder_binding_across_proto(
) -> Result<(), wallet::WalletTypesError> {
    let mut record = record()?;
    record.format = wallet::CredentialFormat::ReallyMeZkV1;
    let proto = credential_record_to_proto(&record);
    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded == record));
    Ok(())
}

#[test]
fn credential_record_accepts_legacy_missing_holder_key_handle(
) -> Result<(), wallet::WalletTypesError> {
    let mut proto = credential_record_to_proto(&record()?);
    proto.holder_key_handle_id.clear();

    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded.holder_key_handle_id.is_none()));
    Ok(())
}

#[test]
fn credential_record_accepts_legacy_missing_signed_issuer() -> Result<(), wallet::WalletTypesError>
{
    let mut proto = credential_record_to_proto(&record()?);
    proto.signed_issuer.clear();

    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(decoded, Ok(decoded) if decoded.signed_issuer.is_none()));
    Ok(())
}

#[test]
fn credential_record_rejects_malformed_holder_key_handle() -> Result<(), wallet::WalletTypesError> {
    let mut proto = credential_record_to_proto(&record()?);
    proto.holder_key_handle_id = "holder\nkey".to_owned();

    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(
        decoded,
        Err(error) if error.reason == ConvertErrorReason::InvalidIdentifier
    ));
    Ok(())
}

#[test]
fn credential_record_rejects_oversized_holder_key_handle() -> Result<(), wallet::WalletTypesError> {
    let mut proto = credential_record_to_proto(&record()?);
    proto.holder_key_handle_id = "k".repeat(257);

    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(
        decoded,
        Err(error) if error.reason == ConvertErrorReason::InvalidIdentifier
    ));
    Ok(())
}

#[test]
fn credential_record_rejects_malformed_signed_issuer() -> Result<(), wallet::WalletTypesError> {
    let mut proto = credential_record_to_proto(&record()?);
    proto.signed_issuer = "https://issuer.example\nforged".to_owned();

    let decoded = credential_record_from_proto(&proto);

    assert!(matches!(
        decoded,
        Err(error) if error.reason == ConvertErrorReason::InvalidIdentifier
    ));
    Ok(())
}

#[test]
fn credential_record_enforces_the_signed_issuer_boundary() -> Result<(), wallet::WalletTypesError> {
    let mut exact = credential_record_to_proto(&record()?);
    exact.signed_issuer = "i".repeat(wallet::MAX_SIGNED_CREDENTIAL_ISSUER_BYTES);
    let mut oversized = credential_record_to_proto(&record()?);
    oversized.signed_issuer =
        "i".repeat(wallet::MAX_SIGNED_CREDENTIAL_ISSUER_BYTES.saturating_add(1));

    assert!(credential_record_from_proto(&exact).is_ok());
    assert!(matches!(
        credential_record_from_proto(&oversized),
        Err(error) if error.reason == ConvertErrorReason::InvalidIdentifier
    ));
    Ok(())
}
