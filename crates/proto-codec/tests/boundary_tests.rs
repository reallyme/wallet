// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Malicious-input and canonical ProtoJSON tests for Wallet codecs.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    begin_operation_provider_response, wallet_operation_request, wallet_operation_response,
    wallet_operation_result, wallet_provider_response, BeginOperationProviderResponse,
    CredentialRecord, EncryptedRecord, GetCredentialRecordRequest, GetCredentialRecordResponse,
    ReplayOperationResponse, WalletOperationRequest, WalletOperationResponse,
    WalletOperationResult, WalletProviderResponse, WalletProviderResult,
};
use reallyme_wallet_proto_codec::decode::{
    decode_credential_record, decode_transaction_log_entry, decode_wallet_provider_response,
};
use reallyme_wallet_proto_codec::encode::{
    encode_wallet_operation_response, encode_wallet_provider_response,
};
use reallyme_wallet_proto_codec::{
    wallet_proto_from_json, wallet_proto_to_json, ProtoError, ProtoErrorReason,
    MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES, MAX_WALLET_PROTO_JSON_BYTES,
    MAX_WALLET_PROTO_JSON_NESTING_DEPTH, MAX_WALLET_PROTO_MESSAGE_BYTES,
    MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES,
};

fn get_credential_request() -> WalletOperationRequest {
    let mut request = WalletOperationRequest::default();
    request.operation = Some(wallet_operation_request::Operation::GetCredentialRecord(
        Box::new(GetCredentialRecordRequest {
            credential_id: "credential-1".to_owned(),
            __buffa_unknown_fields: Default::default(),
        }),
    ));
    request
}

#[test]
fn canonical_operation_request_round_trips_through_generated_proto_json() -> Result<(), ProtoError>
{
    let request = get_credential_request();

    let json = wallet_proto_to_json(&request)?;
    let decoded = wallet_proto_from_json::<WalletOperationRequest>(&json)?;

    assert_eq!(decoded, request);
    assert!(json.contains("getCredentialRecord"));
    assert!(json.contains("credentialId"));
    Ok(())
}

#[test]
fn operation_success_response_round_trips_through_generated_proto_json() -> Result<(), ProtoError> {
    let response = WalletOperationResponse {
        outcome: Some(wallet_operation_response::Outcome::Result(Box::new(
            WalletOperationResult {
                result: Some(wallet_operation_result::Result::GetCredentialRecord(
                    Box::default(),
                )),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let json = wallet_proto_to_json(&response)?;
    let decoded = wallet_proto_from_json::<WalletOperationResponse>(&json)?;

    assert_eq!(decoded, response);
    Ok(())
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn oversized_operation_response_is_rejected_before_protobuf_or_protojson_encoding() {
    let oversized_length = MAX_WALLET_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .unwrap_or(MAX_WALLET_PROTO_MESSAGE_BYTES);
    let mut encrypted = EncryptedRecord::default();
    encrypted.ciphertext = vec![0xA5; oversized_length];
    let mut record = CredentialRecord::default();
    record.encrypted_payload = encrypted.into();
    let mut get = GetCredentialRecordResponse::default();
    get.record = record.into();
    let mut result = WalletOperationResult::default();
    result.result = Some(wallet_operation_result::Result::GetCredentialRecord(
        Box::new(get),
    ));
    let mut response = WalletOperationResponse::default();
    response.outcome = Some(wallet_operation_response::Outcome::Result(Box::new(result)));

    for encoding_result in [
        encode_wallet_operation_response(&response).map(|_| ()),
        wallet_proto_to_json(&response).map(|_| ()),
    ] {
        assert!(matches!(
            encoding_result,
            Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
        ));
    }
}

#[test]
fn duplicate_operation_keys_are_rejected_with_stable_reason() {
    const DUPLICATE: &str = concat!(
        "{\"getCredentialRecord\":{\"credentialId\":\"one\"},",
        "\"getCredentialRecord\":{\"credentialId\":\"two\"}}"
    );

    let result = wallet_proto_from_json::<WalletOperationRequest>(DUPLICATE);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::JsonDuplicateKey
    ));
}

#[test]
fn parse_failures_after_sensitive_values_fail_closed() {
    let duplicate_after_secret =
        "{\"getCredentialRecord\":{\"credentialId\":\"private-id\",\"credentialId\":\"other\"}}";
    let malformed_array_after_secret =
        "{\"items\":[\"private-value\",{\"nested\":\"private-value\"},invalid]}";

    assert!(matches!(
        wallet_proto_from_json::<WalletOperationRequest>(duplicate_after_secret),
        Err(error) if error.reason == ProtoErrorReason::JsonDuplicateKey
    ));
    assert!(matches!(
        wallet_proto_from_json::<WalletOperationRequest>(malformed_array_after_secret),
        Err(error) if error.reason == ProtoErrorReason::JsonDeserialize
    ));
}

#[test]
fn excessive_proto_json_nesting_is_rejected_before_message_conversion() {
    let nesting = MAX_WALLET_PROTO_JSON_NESTING_DEPTH
        .checked_add(2)
        .unwrap_or(MAX_WALLET_PROTO_JSON_NESTING_DEPTH);
    let capacity = nesting.checked_mul(2).unwrap_or(nesting);
    let mut json = String::with_capacity(capacity);
    json.push_str(&"[".repeat(nesting));
    json.push_str(&"]".repeat(nesting));

    let result = wallet_proto_from_json::<WalletOperationRequest>(&json);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::JsonNestingTooDeep
    ));
}

#[test]
fn oversized_proto_json_is_rejected_before_parsing() {
    let oversized_length = MAX_WALLET_PROTO_JSON_BYTES
        .checked_add(1)
        .unwrap_or(MAX_WALLET_PROTO_JSON_BYTES);
    let oversized = " ".repeat(oversized_length);

    let result = wallet_proto_from_json::<WalletOperationRequest>(&oversized);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
}

#[test]
fn escaped_json_output_stops_at_the_configured_byte_limit() {
    let mut request = get_credential_request();
    if let Some(wallet_operation_request::Operation::GetCredentialRecord(get)) =
        request.operation.as_mut()
    {
        get.credential_id = "\u{0001}".repeat(MAX_WALLET_PROTO_JSON_BYTES / 5);
    }

    assert!(matches!(
        wallet_proto_to_json(&request),
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
}

#[test]
fn oversized_protobuf_is_rejected_before_buffa_decoding() {
    let oversized_length = MAX_WALLET_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .unwrap_or(MAX_WALLET_PROTO_MESSAGE_BYTES);
    let oversized = vec![0_u8; oversized_length];

    let result = decode_credential_record(&oversized);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn provider_replay_envelope_can_wrap_a_maximum_operation_response() -> Result<(), ProtoError> {
    let mut replay = ReplayOperationResponse::default();
    replay.response = vec![0xA5; MAX_WALLET_PROTO_MESSAGE_BYTES];
    let mut begin = BeginOperationProviderResponse::default();
    begin.outcome = Some(begin_operation_provider_response::Outcome::Replay(
        Box::new(replay),
    ));
    let mut result = WalletProviderResult::default();
    result.result = begin.into();
    let mut response = WalletProviderResponse::default();
    response.contract_version = 1;
    response.executor_id = 1;
    response.request_id = 1;
    response.outcome = Some(wallet_provider_response::Outcome::Result(Box::new(result)));

    let encoded = encode_wallet_provider_response(&response)?;
    assert!(encoded.len() > MAX_WALLET_PROTO_MESSAGE_BYTES);
    assert!(encoded.len() <= MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES);
    assert_eq!(decode_wallet_provider_response(&encoded)?, response);
    Ok(())
}

#[test]
fn oversized_provider_protobuf_is_rejected_before_decoding() {
    let oversized_length = MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .unwrap_or(MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES);
    let oversized = vec![0_u8; oversized_length];

    let result = decode_wallet_provider_response(&oversized);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
}

#[test]
fn unknown_protobuf_fields_fail_closed() {
    // Field 99, varint wire type, value zero. CredentialRecord has no field 99.
    const UNKNOWN_FIELD: &[u8] = &[0x98, 0x06, 0x00];

    let result = decode_credential_record(UNKNOWN_FIELD);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::UnknownFieldLimitExceeded
    ));
}

#[test]
fn malformed_proto_json_shape_has_stable_typed_error() {
    let result = wallet_proto_from_json::<WalletOperationRequest>("{\"result\":{}}");

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::JsonDeserialize
    ));
}

#[test]
fn unknown_proto_json_enum_fails_closed() {
    const UNKNOWN_ENUM: &str = concat!(
        "{\"applyWalletLifecycleEvent\":{",
        "\"walletInstanceId\":\"wallet-unit-1\",",
        "\"event\":\"WALLET_LIFECYCLE_EVENT_UNKNOWN_TO_THIS_SCHEMA\",",
        "\"now\":{\"seconds\":\"11\"}}}"
    );

    let result = wallet_proto_from_json::<WalletOperationRequest>(UNKNOWN_ENUM);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::JsonDeserialize
    ));
}

#[test]
fn unknown_proto_json_field_fails_closed() {
    const UNKNOWN_FIELD: &str = concat!(
        "{\"getCredentialRecord\":{",
        "\"credentialId\":\"credential-1\",",
        "\"unrecognizedField\":true}}"
    );

    let result = wallet_proto_from_json::<WalletOperationRequest>(UNKNOWN_FIELD);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::JsonDeserialize
    ));
}

#[test]
fn trailing_proto_json_value_fails_closed() {
    let result = wallet_proto_from_json::<WalletOperationRequest>("{}[]");

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::JsonDeserialize
    ));
}

#[test]
fn malicious_proto_json_shapes_fail_closed() {
    for malformed in [
        "null",
        "[]",
        "true",
        "{\"getCredentialRecord\":[]}",
        "{\"getCredentialRecord\":{\"credentialId\":[]}}",
    ] {
        let result = wallet_proto_from_json::<WalletOperationRequest>(malformed);
        assert!(matches!(
            result,
            Err(error) if error.reason == ProtoErrorReason::JsonDeserialize
        ));
    }
}

/// buffa's own element-memory budget when none is configured.
const BUFFA_DEFAULT_ELEMENT_MEMORY_BYTES: usize = 32 * 1_048_576;

#[test]
fn repeated_empty_submessages_cannot_amplify_decode_memory() {
    // Field 4 (`disclosed_attributes`) as an empty length-delimited element is
    // two wire bytes, but costs one element struct to materialize. Sending
    // just enough elements to pass the Wallet budget, while staying under
    // buffa's default budget and the message limit, shows the Wallet budget
    // is the one applied.
    let element_bytes = core::mem::size_of::<
        reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::DisclosedAttribute,
    >();
    let element_count = MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES / element_bytes + 1;
    assert!(element_count * element_bytes < BUFFA_DEFAULT_ELEMENT_MEMORY_BYTES);
    assert!(element_count * 2 < MAX_WALLET_PROTO_MESSAGE_BYTES);
    let mut bytes = Vec::with_capacity(element_count * 2);
    for _ in 0..element_count {
        bytes.extend_from_slice(&[0x22, 0x00]);
    }

    let result = decode_transaction_log_entry(&bytes);

    assert!(matches!(
        result,
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
}
