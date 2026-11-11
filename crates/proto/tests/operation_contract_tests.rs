// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contract tests for the canonical wallet operation envelope.

#![cfg(feature = "generated")]
#![allow(clippy::unwrap_used)]

use buffa::Message;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    wallet_operation_request, wallet_operation_response, wallet_operation_result,
    AppendQtspDecisionRequest, AppendQtspDecisionResponse, AppendTransactionLogRequest,
    AppendTransactionLogResponse, AppendWalletLifecycleEvidenceRequest,
    AppendWalletLifecycleEvidenceResponse, ApplyCredentialStatusEvidenceRequest,
    ApplyCredentialStatusEvidenceResponse, ApplyWalletLifecycleEventRequest,
    ApplyWalletLifecycleEventResponse, ClaimPresentationCopyRequest, ClaimPresentationCopyResponse,
    DeleteCredentialRecordRequest, DeleteCredentialRecordResponse,
    EvaluateVerifierEntitlementRequest, EvaluateVerifierEntitlementResponse,
    GetCredentialRecordRequest, GetCredentialRecordResponse, GetFlowSnapshotRequest,
    GetFlowSnapshotResponse, GetWalletLifecycleRecordRequest, GetWalletLifecycleRecordResponse,
    PutCredentialRecordRequest, PutCredentialRecordResponse, PutWalletLifecycleRecordRequest,
    PutWalletLifecycleRecordResponse, SaveFlowSnapshotRequest, SaveFlowSnapshotResponse,
    WalletOperationRequest, WalletOperationResponse, WalletOperationResult,
};

const WIRE_TYPE_LENGTH_DELIMITED: u32 = 2;
const PROTOBUF_FIELD_TAG_SHIFT: u32 = 3;

fn encode_varint(mut value: u32) -> Vec<u8> {
    let mut encoded = Vec::new();

    while value >= 0x80 {
        let byte = u8::try_from((value & 0x7f) | 0x80).unwrap();
        encoded.push(byte);
        value >>= 7;
    }

    encoded.push(u8::try_from(value).unwrap());
    encoded
}

fn length_delimited_tag(field_number: u32) -> Vec<u8> {
    let shifted = field_number.checked_shl(PROTOBUF_FIELD_TAG_SHIFT).unwrap();
    let tag = shifted.checked_add(WIRE_TYPE_LENGTH_DELIMITED).unwrap();
    encode_varint(tag)
}

fn request_variants() -> Vec<(u32, wallet_operation_request::Operation)> {
    vec![
        (1001, PutWalletLifecycleRecordRequest::default().into()),
        (1002, GetWalletLifecycleRecordRequest::default().into()),
        (1003, ApplyWalletLifecycleEventRequest::default().into()),
        (1004, AppendWalletLifecycleEvidenceRequest::default().into()),
        (2001, PutCredentialRecordRequest::default().into()),
        (2002, GetCredentialRecordRequest::default().into()),
        (2003, ApplyCredentialStatusEvidenceRequest::default().into()),
        (2004, DeleteCredentialRecordRequest::default().into()),
        (2005, ClaimPresentationCopyRequest::default().into()),
        (3001, EvaluateVerifierEntitlementRequest::default().into()),
        (5001, SaveFlowSnapshotRequest::default().into()),
        (5002, GetFlowSnapshotRequest::default().into()),
        (6001, AppendTransactionLogRequest::default().into()),
        (6002, AppendQtspDecisionRequest::default().into()),
    ]
}

fn result_variants() -> Vec<(u32, wallet_operation_result::Result)> {
    vec![
        (1001, PutWalletLifecycleRecordResponse::default().into()),
        (1002, GetWalletLifecycleRecordResponse::default().into()),
        (1003, ApplyWalletLifecycleEventResponse::default().into()),
        (
            1004,
            AppendWalletLifecycleEvidenceResponse::default().into(),
        ),
        (2001, PutCredentialRecordResponse::default().into()),
        (2002, GetCredentialRecordResponse::default().into()),
        (
            2003,
            ApplyCredentialStatusEvidenceResponse::default().into(),
        ),
        (2004, DeleteCredentialRecordResponse::default().into()),
        (2005, ClaimPresentationCopyResponse::default().into()),
        (3001, EvaluateVerifierEntitlementResponse::default().into()),
        (5001, SaveFlowSnapshotResponse::default().into()),
        (5002, GetFlowSnapshotResponse::default().into()),
        (6001, AppendTransactionLogResponse::default().into()),
        (6002, AppendQtspDecisionResponse::default().into()),
    ]
}

#[test]
fn every_operation_request_variant_round_trips_at_its_stable_field_number() {
    for (field_number, operation) in request_variants() {
        let mut request = WalletOperationRequest::default();
        request.operation = Some(operation);

        let encoded = request.encode_to_vec();
        assert!(encoded.starts_with(&length_delimited_tag(field_number)));

        let decoded = WalletOperationRequest::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }
}

#[test]
fn every_operation_result_variant_round_trips_at_its_paired_field_number() {
    for (field_number, result) in result_variants() {
        let operation_result = WalletOperationResult {
            result: Some(result),
            __buffa_unknown_fields: Default::default(),
        };

        let encoded = operation_result.encode_to_vec();
        assert!(encoded.starts_with(&length_delimited_tag(field_number)));

        let decoded = WalletOperationResult::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, operation_result);
    }
}

#[test]
fn operation_response_round_trips_success_and_typed_error_outcomes() {
    let success = WalletOperationResponse {
        outcome: Some(wallet_operation_response::Outcome::Result(Box::new(
            WalletOperationResult {
                result: Some(PutCredentialRecordResponse::default().into()),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let error = WalletOperationResponse {
        outcome: Some(wallet_operation_response::Outcome::Error(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };

    for response in [success, error] {
        let encoded = response.encode_to_vec();
        let decoded = WalletOperationResponse::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, response);
    }
}
