// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-language golden tests for the canonical version-1 operation boundary.

use buffa::{EnumValue, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1::CredentialFormat;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::AeadAlgorithm;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    wallet_operation_response, wallet_operation_result, CredentialLifecycleStatus,
    CredentialRecord, DeleteCredentialRecordRequest, DeleteCredentialRecordResponse,
    EncryptedRecord, EncryptedRecordHeader, GetCredentialRecordRequest, PutCredentialRecordRequest,
    UnixTimestamp, WalletOperationRequest, WalletOperationResponse, WalletOperationResult,
};
use reallyme_wallet_proto_codec::decode::{
    decode_wallet_operation_request, decode_wallet_operation_response,
};
use reallyme_wallet_proto_codec::encode::{
    encode_wallet_operation_request, encode_wallet_operation_response,
};
use reallyme_wallet_proto_codec::{wallet_proto_from_json, wallet_proto_to_json};
use serde::Deserialize;

const FIXTURE_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/wallet-operation-v1-golden.json"
));

#[derive(Deserialize)]
struct FixtureSet {
    schema_version: u32,
    protobuf_package: String,
    cases: Vec<FixtureCase>,
}

#[derive(Deserialize)]
struct FixtureCase {
    id: String,
    message_type: String,
    protobuf_hex: String,
    protojson: String,
}

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error("fixture_json")]
    Json,
    #[error("fixture_hex")]
    Hex,
    #[error("fixture_contract")]
    Contract,
    #[error("fixture_codec")]
    Codec,
}

fn decode_hex(value: &str) -> Result<Vec<u8>, FixtureError> {
    if !value.len().is_multiple_of(2) {
        return Err(FixtureError::Hex);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).map_err(|_| FixtureError::Hex)?;
            u8::from_str_radix(text, 16).map_err(|_| FixtureError::Hex)
        })
        .collect()
}

fn request_fixture() -> WalletOperationRequest {
    let mut request = WalletOperationRequest::default();
    request.operation = GetCredentialRecordRequest {
        credential_id: "credential-golden-1".to_owned(),
        __buffa_unknown_fields: Default::default(),
    }
    .into();
    request
}

fn mutating_request_fixture() -> WalletOperationRequest {
    let mut request = WalletOperationRequest::default();
    request.idempotency_key = vec![0xA5; 32];
    request.operation = DeleteCredentialRecordRequest {
        credential_id: "credential-golden-1".to_owned(),
        __buffa_unknown_fields: Default::default(),
    }
    .into();
    request
}

fn encrypted_put_request_fixture() -> WalletOperationRequest {
    let timestamp = || UnixTimestamp {
        seconds: 1,
        ..UnixTimestamp::default()
    };
    let header = EncryptedRecordHeader {
        schema_version: 1,
        key_handle_id: "key-golden-1".to_owned(),
        created_at: MessageField::some(timestamp()),
        encryption_algorithm: EnumValue::from(AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM_SIV),
        __buffa_unknown_fields: Default::default(),
    };
    let encrypted_payload = EncryptedRecord {
        header: MessageField::some(header),
        nonce: vec![1; 12],
        aad: vec![2, 3],
        ciphertext: vec![4; 16],
        __buffa_unknown_fields: Default::default(),
    };
    let record = CredentialRecord {
        id: "credential-golden-2".to_owned(),
        issuer_id: "issuer-golden-1".to_owned(),
        signed_issuer: "https://issuer.example".to_owned(),
        holder_key_handle_id: "holder-key-golden-1".to_owned(),
        status_reference: MessageField::none(),
        format: EnumValue::from(CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT),
        status: EnumValue::from(CredentialLifecycleStatus::CREDENTIAL_LIFECYCLE_STATUS_ACTIVE),
        received_at: MessageField::some(timestamp()),
        encrypted_payload: MessageField::some(encrypted_payload),
        __buffa_unknown_fields: Default::default(),
    };

    let mut request = WalletOperationRequest::default();
    request.idempotency_key = vec![0x5A; 32];
    request.operation = PutCredentialRecordRequest {
        record: MessageField::some(record),
        __buffa_unknown_fields: Default::default(),
    }
    .into();
    request
}

fn response_fixture() -> WalletOperationResponse {
    WalletOperationResponse {
        outcome: Some(wallet_operation_response::Outcome::Result(Box::new(
            WalletOperationResult {
                result: Some(wallet_operation_result::Result::DeleteCredentialRecord(
                    Box::<DeleteCredentialRecordResponse>::default(),
                )),
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

#[test]
fn operation_golden_fixtures_match_protobuf_and_protojson() -> Result<(), FixtureError> {
    let fixtures: FixtureSet =
        serde_json::from_str(FIXTURE_SOURCE).map_err(|_| FixtureError::Json)?;
    if fixtures.schema_version != 1 || fixtures.protobuf_package != "reallyme.wallet.v1" {
        return Err(FixtureError::Contract);
    }
    if fixtures.cases.len() != 4 {
        return Err(FixtureError::Contract);
    }

    for fixture in fixtures.cases {
        let expected_bytes = decode_hex(&fixture.protobuf_hex)?;
        match (fixture.id.as_str(), fixture.message_type.as_str()) {
            ("get-credential-request", "WalletOperationRequest") => {
                let message = request_fixture();
                let encoded =
                    encode_wallet_operation_request(&message).map_err(|_| FixtureError::Codec)?;
                let json = wallet_proto_to_json(&message).map_err(|_| FixtureError::Codec)?;
                if encoded.as_slice() != expected_bytes || json.as_str() != fixture.protojson {
                    return Err(FixtureError::Contract);
                }
                let decoded = decode_wallet_operation_request(&expected_bytes)
                    .map_err(|_| FixtureError::Codec)?;
                let decoded_json =
                    wallet_proto_from_json::<WalletOperationRequest>(&fixture.protojson)
                        .map_err(|_| FixtureError::Codec)?;
                if decoded != message || decoded_json != message {
                    return Err(FixtureError::Contract);
                }
            }
            ("delete-credential-idempotent-request", "WalletOperationRequest") => {
                let message = mutating_request_fixture();
                let encoded =
                    encode_wallet_operation_request(&message).map_err(|_| FixtureError::Codec)?;
                let json = wallet_proto_to_json(&message).map_err(|_| FixtureError::Codec)?;
                if encoded.as_slice() != expected_bytes || json.as_str() != fixture.protojson {
                    return Err(FixtureError::Contract);
                }
                let decoded = decode_wallet_operation_request(&expected_bytes)
                    .map_err(|_| FixtureError::Codec)?;
                let decoded_json =
                    wallet_proto_from_json::<WalletOperationRequest>(&fixture.protojson)
                        .map_err(|_| FixtureError::Codec)?;
                if decoded != message || decoded_json != message {
                    return Err(FixtureError::Contract);
                }
            }
            ("put-encrypted-credential-request", "WalletOperationRequest") => {
                let message = encrypted_put_request_fixture();
                let encoded =
                    encode_wallet_operation_request(&message).map_err(|_| FixtureError::Codec)?;
                let json = wallet_proto_to_json(&message).map_err(|_| FixtureError::Codec)?;
                if encoded.as_slice() != expected_bytes || json.as_str() != fixture.protojson {
                    return Err(FixtureError::Contract);
                }
                let decoded = decode_wallet_operation_request(&expected_bytes)
                    .map_err(|_| FixtureError::Codec)?;
                let decoded_json =
                    wallet_proto_from_json::<WalletOperationRequest>(&fixture.protojson)
                        .map_err(|_| FixtureError::Codec)?;
                if decoded != message || decoded_json != message {
                    return Err(FixtureError::Contract);
                }
            }
            ("delete-credential-success-response", "WalletOperationResponse") => {
                let message = response_fixture();
                let encoded =
                    encode_wallet_operation_response(&message).map_err(|_| FixtureError::Codec)?;
                let json = wallet_proto_to_json(&message).map_err(|_| FixtureError::Codec)?;
                if encoded.as_slice() != expected_bytes || json.as_str() != fixture.protojson {
                    return Err(FixtureError::Contract);
                }
                let decoded = decode_wallet_operation_response(&expected_bytes)
                    .map_err(|_| FixtureError::Codec)?;
                let decoded_json =
                    wallet_proto_from_json::<WalletOperationResponse>(&fixture.protojson)
                        .map_err(|_| FixtureError::Codec)?;
                if decoded != message || decoded_json != message {
                    return Err(FixtureError::Contract);
                }
            }
            _ => return Err(FixtureError::Contract),
        }
    }

    Ok(())
}
