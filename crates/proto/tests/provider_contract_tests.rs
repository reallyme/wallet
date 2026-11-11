// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contract tests for the versioned platform-provider message boundary.

#![cfg(feature = "generated")]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Message};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    wallet_provider_request, wallet_provider_response, wallet_provider_result,
    AppendQtspDecisionProviderRequest, AppendQtspDecisionProviderResponse,
    AppendTransactionLogProviderRequest, AppendTransactionLogProviderResponse,
    AppendWalletLifecycleEvidenceProviderRequest, AppendWalletLifecycleEvidenceProviderResponse,
    BeginOperationProviderRequest, BeginOperationProviderResponse,
    ClaimPresentationCopyProviderRequest, ClaimPresentationCopyProviderResponse,
    CommitOperationProviderRequest, CommitOperationProviderResponse,
    CompareAndSwapCredentialProviderRequest, CompareAndSwapCredentialProviderResponse,
    CompareAndSwapWalletLifecycleProviderRequest, CompareAndSwapWalletLifecycleProviderResponse,
    CreateCredentialProviderRequest, CreateCredentialProviderResponse,
    CreateWalletLifecycleProviderRequest, CreateWalletLifecycleProviderResponse,
    DeleteCredentialProviderRequest, DeleteCredentialProviderResponse,
    GetCredentialProviderRequest, GetCredentialProviderResponse, GetFlowSnapshotProviderRequest,
    GetFlowSnapshotProviderResponse, GetWalletLifecycleProviderRequest,
    GetWalletLifecycleProviderResponse, SaveFlowSnapshotProviderRequest,
    SaveFlowSnapshotProviderResponse, WalletProviderCapability, WalletProviderDescriptor,
    WalletProviderError, WalletProviderErrorReason, WalletProviderInvocationMode,
    WalletProviderRequest, WalletProviderResponse, WalletProviderResult,
};

const WIRE_TYPE_LENGTH_DELIMITED: u32 = 2;
const PROTOBUF_FIELD_TAG_SHIFT: u32 = 3;

fn encode_varint(mut value: u32) -> Vec<u8> {
    let mut encoded = Vec::new();
    while value >= 0x80 {
        encoded.push(u8::try_from((value & 0x7f) | 0x80).unwrap());
        value >>= 7;
    }
    encoded.push(u8::try_from(value).unwrap());
    encoded
}

fn length_delimited_tag(field_number: u32) -> Vec<u8> {
    let shifted = field_number.checked_shl(PROTOBUF_FIELD_TAG_SHIFT).unwrap();
    encode_varint(shifted.checked_add(WIRE_TYPE_LENGTH_DELIMITED).unwrap())
}

fn request_variants() -> Vec<(u32, wallet_provider_request::Request)> {
    vec![
        (10, BeginOperationProviderRequest::default().into()),
        (11, CommitOperationProviderRequest::default().into()),
        (1001, CreateWalletLifecycleProviderRequest::default().into()),
        (1002, GetWalletLifecycleProviderRequest::default().into()),
        (
            1003,
            CompareAndSwapWalletLifecycleProviderRequest::default().into(),
        ),
        (
            1004,
            AppendWalletLifecycleEvidenceProviderRequest::default().into(),
        ),
        (2001, CreateCredentialProviderRequest::default().into()),
        (2002, GetCredentialProviderRequest::default().into()),
        (
            2003,
            CompareAndSwapCredentialProviderRequest::default().into(),
        ),
        (2004, DeleteCredentialProviderRequest::default().into()),
        (2005, ClaimPresentationCopyProviderRequest::default().into()),
        (5001, SaveFlowSnapshotProviderRequest::default().into()),
        (5002, GetFlowSnapshotProviderRequest::default().into()),
        (6001, AppendTransactionLogProviderRequest::default().into()),
        (6002, AppendQtspDecisionProviderRequest::default().into()),
    ]
}

fn result_variants() -> Vec<(u32, wallet_provider_result::Result)> {
    vec![
        (10, BeginOperationProviderResponse::default().into()),
        (11, CommitOperationProviderResponse::default().into()),
        (
            1001,
            CreateWalletLifecycleProviderResponse::default().into(),
        ),
        (1002, GetWalletLifecycleProviderResponse::default().into()),
        (
            1003,
            CompareAndSwapWalletLifecycleProviderResponse::default().into(),
        ),
        (
            1004,
            AppendWalletLifecycleEvidenceProviderResponse::default().into(),
        ),
        (2001, CreateCredentialProviderResponse::default().into()),
        (2002, GetCredentialProviderResponse::default().into()),
        (
            2003,
            CompareAndSwapCredentialProviderResponse::default().into(),
        ),
        (2004, DeleteCredentialProviderResponse::default().into()),
        (
            2005,
            ClaimPresentationCopyProviderResponse::default().into(),
        ),
        (5001, SaveFlowSnapshotProviderResponse::default().into()),
        (5002, GetFlowSnapshotProviderResponse::default().into()),
        (6001, AppendTransactionLogProviderResponse::default().into()),
        (6002, AppendQtspDecisionProviderResponse::default().into()),
    ]
}

#[test]
// Hardened generated owners implement Drop and therefore cannot use struct
// update syntax without attempting to move their hidden fields.
#[allow(clippy::field_reassign_with_default)]
fn every_provider_request_round_trips_at_its_stable_field_number() {
    for (field_number, variant) in request_variants() {
        let mut request = WalletProviderRequest::default();
        request.request = Some(variant);

        let encoded = request.encode_to_vec();
        assert!(encoded.starts_with(&length_delimited_tag(field_number)));
        let decoded = WalletProviderRequest::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }
}

#[test]
// See the request test above; the result envelope is also a hardened owner.
#[allow(clippy::field_reassign_with_default)]
fn every_provider_result_round_trips_at_the_paired_field_number() {
    for (field_number, variant) in result_variants() {
        let mut result = WalletProviderResult::default();
        result.result = Some(variant);

        let encoded = result.encode_to_vec();
        assert!(encoded.starts_with(&length_delimited_tag(field_number)));
        let decoded = WalletProviderResult::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, result);
    }
}

#[test]
// WalletProviderResponse is a hardened owner and must be populated explicitly.
#[allow(clippy::field_reassign_with_default)]
fn descriptor_and_typed_error_preserve_version_and_correlation() {
    let descriptor = WalletProviderDescriptor {
        contract_version: 1,
        invocation_mode: EnumValue::from(
            WalletProviderInvocationMode::WALLET_PROVIDER_INVOCATION_MODE_SYNCHRONOUS_NATIVE,
        ),
        capabilities: vec![EnumValue::from(
            WalletProviderCapability::WALLET_PROVIDER_CAPABILITY_BEGIN_OPERATION,
        )],
        max_response_bytes: 4096,
        ..Default::default()
    };
    let encoded_descriptor = descriptor.encode_to_vec();
    assert_eq!(
        WalletProviderDescriptor::decode(&mut encoded_descriptor.as_slice()).unwrap(),
        descriptor
    );

    let mut error = WalletProviderError::default();
    error.reason =
        EnumValue::from(WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT);
    let mut response = WalletProviderResponse::default();
    response.contract_version = 1;
    response.executor_id = 9;
    response.request_id = 17;
    response.outcome = Some(wallet_provider_response::Outcome::Error(Box::new(error)));
    let encoded_response = response.encode_to_vec();
    assert_eq!(
        WalletProviderResponse::decode(&mut encoded_response.as_slice()).unwrap(),
        response
    );
}
