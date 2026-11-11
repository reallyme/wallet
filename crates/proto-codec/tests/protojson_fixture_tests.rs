// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checked-in canonical and malicious ProtoJSON fixture regressions.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    wallet_operation_request, wallet_operation_response, wallet_operation_result,
    WalletOperationRequest, WalletOperationResponse,
};
use reallyme_wallet_proto_codec::{wallet_proto_from_json, ProtoError, ProtoErrorReason};

const GET_CREDENTIAL_REQUEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/protojson/get-credential-request.json"
));
const DELETE_CREDENTIAL_RESPONSE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/protojson/delete-credential-success-response.json"
));
const MALICIOUS_DUPLICATE_OPERATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/protojson/malicious-duplicate-operation.json"
));
const MALICIOUS_UNKNOWN_FIELD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/protojson/malicious-unknown-field.json"
));
const MALICIOUS_UNKNOWN_ENUM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/protojson/malicious-unknown-enum.json"
));
const MALICIOUS_WRONG_SHAPE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proto/protojson/malicious-wrong-shape.json"
));
const FUZZ_GET_CREDENTIAL_REQUEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fuzz/get-credential-request.json"
));
const FUZZ_DELETE_CREDENTIAL_RESPONSE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fuzz/delete-credential-success-response.json"
));
const FUZZ_MALICIOUS_DUPLICATE_OPERATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fuzz/malicious-duplicate-operation.json"
));
const FUZZ_MALICIOUS_UNKNOWN_FIELD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fuzz/malicious-unknown-field.json"
));
const FUZZ_MALICIOUS_UNKNOWN_ENUM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fuzz/malicious-unknown-enum.json"
));
const FUZZ_MALICIOUS_WRONG_SHAPE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fuzz/malicious-wrong-shape.json"
));

#[test]
fn protojson_fuzz_seeds_are_exact_copies_of_reviewed_contract_fixtures() {
    for (fixture, fuzz_seed) in [
        (GET_CREDENTIAL_REQUEST, FUZZ_GET_CREDENTIAL_REQUEST),
        (DELETE_CREDENTIAL_RESPONSE, FUZZ_DELETE_CREDENTIAL_RESPONSE),
        (
            MALICIOUS_DUPLICATE_OPERATION,
            FUZZ_MALICIOUS_DUPLICATE_OPERATION,
        ),
        (MALICIOUS_UNKNOWN_FIELD, FUZZ_MALICIOUS_UNKNOWN_FIELD),
        (MALICIOUS_UNKNOWN_ENUM, FUZZ_MALICIOUS_UNKNOWN_ENUM),
        (MALICIOUS_WRONG_SHAPE, FUZZ_MALICIOUS_WRONG_SHAPE),
    ] {
        assert_eq!(fixture.as_bytes(), fuzz_seed.as_bytes());
    }
}

#[test]
fn canonical_protojson_fixtures_decode_to_the_expected_operation_variants() -> Result<(), ProtoError>
{
    let request = wallet_proto_from_json::<WalletOperationRequest>(GET_CREDENTIAL_REQUEST)?;
    assert!(matches!(
        request.operation.as_ref(),
        Some(wallet_operation_request::Operation::GetCredentialRecord(value))
            if value.credential_id == "credential-golden-1"
    ));

    let response = wallet_proto_from_json::<WalletOperationResponse>(DELETE_CREDENTIAL_RESPONSE)?;
    assert!(matches!(
        response.outcome.as_ref(),
        Some(wallet_operation_response::Outcome::Result(result))
            if matches!(
                result.result.as_ref(),
                Some(wallet_operation_result::Result::DeleteCredentialRecord(_))
            )
    ));
    Ok(())
}

#[test]
fn malicious_protojson_fixtures_fail_with_stable_typed_reasons() {
    for (fixture, expected_reason) in [
        (
            MALICIOUS_DUPLICATE_OPERATION,
            ProtoErrorReason::JsonDuplicateKey,
        ),
        (MALICIOUS_UNKNOWN_FIELD, ProtoErrorReason::JsonDeserialize),
        (MALICIOUS_UNKNOWN_ENUM, ProtoErrorReason::JsonDeserialize),
        (MALICIOUS_WRONG_SHAPE, ProtoErrorReason::JsonDeserialize),
    ] {
        let result = wallet_proto_from_json::<WalletOperationRequest>(fixture);
        assert!(matches!(
            result,
            Err(error) if error.reason == expected_reason
        ));
    }
}
