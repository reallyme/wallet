// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(
    clippy::unwrap_used,
    reason = "test fixture construction and assertions"
)]

use reallyme_wallet_types::{
    EncryptedRecord, EncryptedRecordHeader, KeyHandleId, NonEmptyIdentifier, PresentationCopyId,
    StorageEncryptionAlgorithm, UnixTimestamp,
};
use zeroize::Zeroizing;

use super::{
    decode_prepared_private_token, encode_prepared_private_token,
    prepared_private_token_aad_digest, validate_prepared_private_token_record,
    PreparedPrivateTokenPayload,
};
use crate::{ProtoErrorReason, MAX_WALLET_PROTO_MESSAGE_BYTES};

fn token() -> PreparedPrivateTokenPayload {
    let copy_id = PresentationCopyId::new("copy-1".to_owned()).unwrap();
    let credential_id = NonEmptyIdentifier::new("credential-1".to_owned()).unwrap();
    let key_id = KeyHandleId::new("key-1".to_owned()).unwrap();
    let wallet_id = NonEmptyIdentifier::new("wallet-1".to_owned()).unwrap();
    PreparedPrivateTokenPayload::try_new(
        copy_id,
        credential_id,
        Zeroizing::new(vec![0x0a, 0x01, 0x01]),
        key_id,
        wallet_id,
    )
    .unwrap()
}

#[test]
fn private_token_round_trips_with_bound_identifiers() {
    let token = token();
    let encoded = encode_prepared_private_token(&token).unwrap();
    let decoded =
        decode_prepared_private_token(&encoded, token.copy_id(), token.credential_id()).unwrap();
    assert_eq!(decoded.copy_id().as_str(), "copy-1");
    assert_eq!(decoded.credential_id().as_str(), "credential-1");
    assert_eq!(decoded.one_time_key_handle_id().as_str(), "key-1");
    assert_eq!(decoded.wallet_instance_id().as_str(), "wallet-1");
    assert_eq!(decoded.prepared_credential_evidence(), &[0x0a, 0x01, 0x01]);
}

#[test]
fn private_token_rejects_copy_and_credential_substitution() {
    let token = token();
    let encoded = encode_prepared_private_token(&token).unwrap();
    let other_copy = PresentationCopyId::new("copy-2".to_owned()).unwrap();
    let other_credential = NonEmptyIdentifier::new("credential-2".to_owned()).unwrap();
    assert_eq!(
        decode_prepared_private_token(&encoded, &other_copy, token.credential_id())
            .err()
            .unwrap()
            .reason,
        ProtoErrorReason::InvalidDto
    );
    assert_eq!(
        decode_prepared_private_token(&encoded, token.copy_id(), &other_credential)
            .err()
            .unwrap()
            .reason,
        ProtoErrorReason::InvalidDto
    );
}

#[test]
fn private_token_rejects_unknown_fields_and_oversize() {
    let token = token();
    let mut encoded = encode_prepared_private_token(&token).unwrap();
    encoded.extend_from_slice(&[0x30, 0x01]);
    assert!(
        decode_prepared_private_token(&encoded, token.copy_id(), token.credential_id()).is_err()
    );
    let oversized = vec![0; MAX_WALLET_PROTO_MESSAGE_BYTES + 1];
    assert_eq!(
        decode_prepared_private_token(&oversized, token.copy_id(), token.credential_id())
            .err()
            .unwrap()
            .reason,
        ProtoErrorReason::MessageTooLarge
    );
}

#[test]
fn private_token_rejects_missing_evidence() {
    let token = token();
    let empty = PreparedPrivateTokenPayload::try_new(
        PresentationCopyId::new(token.copy_id().as_str().to_owned()).unwrap(),
        NonEmptyIdentifier::new(token.credential_id().as_str().to_owned()).unwrap(),
        Zeroizing::new(Vec::new()),
        KeyHandleId::new("key-1".to_owned()).unwrap(),
        NonEmptyIdentifier::new("wallet-1".to_owned()).unwrap(),
    );
    assert_eq!(empty.err().unwrap().reason, ProtoErrorReason::InvalidDto);
}

#[test]
fn private_token_aad_binds_claimed_copy_and_record_header() {
    let token = token();
    let header = EncryptedRecordHeader {
        schema_version: 1,
        key_handle_id: KeyHandleId::new("storage-key-1".to_owned()).unwrap(),
        algorithm: StorageEncryptionAlgorithm::Aes256GcmSiv,
        created_at: UnixTimestamp::from_seconds(123).unwrap(),
    };
    let aad =
        prepared_private_token_aad_digest(token.copy_id(), token.credential_id(), &header).unwrap();
    let record = EncryptedRecord {
        header,
        nonce: vec![1; 12],
        aad: aad.to_vec(),
        ciphertext: vec![2; 32],
    };
    validate_prepared_private_token_record(token.copy_id(), token.credential_id(), &record)
        .unwrap();
    let other_copy = PresentationCopyId::new("copy-2".to_owned()).unwrap();
    assert_eq!(
        validate_prepared_private_token_record(&other_copy, token.credential_id(), &record)
            .err()
            .unwrap()
            .reason,
        ProtoErrorReason::InvalidDto
    );
    let other_credential = NonEmptyIdentifier::new("credential-2".to_owned()).unwrap();
    assert_eq!(
        validate_prepared_private_token_record(token.copy_id(), &other_credential, &record)
            .err()
            .unwrap()
            .reason,
        ProtoErrorReason::InvalidDto
    );
    let mut wrong_nonce = record.clone();
    wrong_nonce.nonce.pop();
    assert_eq!(
        validate_prepared_private_token_record(
            token.copy_id(),
            token.credential_id(),
            &wrong_nonce,
        )
        .err()
        .unwrap()
        .reason,
        ProtoErrorReason::InvalidDto
    );
    let mut wrong_header = record.clone();
    wrong_header.header.created_at = UnixTimestamp::from_seconds(124).unwrap();
    assert_eq!(
        validate_prepared_private_token_record(
            token.copy_id(),
            token.credential_id(),
            &wrong_header,
        )
        .err()
        .unwrap()
        .reason,
        ProtoErrorReason::InvalidDto
    );
    let mut oversized_record = record.clone();
    oversized_record.ciphertext = vec![0; MAX_WALLET_PROTO_MESSAGE_BYTES + 17];
    assert_eq!(
        validate_prepared_private_token_record(
            token.copy_id(),
            token.credential_id(),
            &oversized_record,
        )
        .err()
        .unwrap()
        .reason,
        ProtoErrorReason::InvalidDto
    );
}
