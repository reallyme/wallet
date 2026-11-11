// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use super::replay_answers_operation;
use crate::{runtime_error_envelope, RuntimeErrorReason};

fn result_response(result: pb::wallet_operation_result::Result) -> pb::WalletOperationResponse {
    pb::WalletOperationResponse {
        outcome: pb::wallet_operation_response::Outcome::Result(Box::new(
            pb::WalletOperationResult {
                result: Some(result),
                ..Default::default()
            },
        ))
        .into(),
        ..Default::default()
    }
}

fn delete_request() -> pb::wallet_operation_request::Operation {
    pb::DeleteCredentialRecordRequest::default().into()
}

#[test]
fn replay_releases_the_matching_result_variant() {
    let response = result_response(pb::DeleteCredentialRecordResponse::default().into());
    assert!(replay_answers_operation(&delete_request(), &response));
}

#[test]
fn replay_releases_a_stored_error() {
    let response = pb::WalletOperationResponse {
        outcome: pb::wallet_operation_response::Outcome::Error(Box::new(runtime_error_envelope(
            RuntimeErrorReason::CredentialRevisionConflict,
        )))
        .into(),
        ..Default::default()
    };
    assert!(replay_answers_operation(&delete_request(), &response));
}

#[test]
fn replay_rejects_a_result_for_another_operation() {
    let response = result_response(pb::GetCredentialRecordResponse::default().into());
    assert!(!replay_answers_operation(&delete_request(), &response));
}

#[test]
fn replay_rejects_an_empty_outcome() {
    let response = pb::WalletOperationResponse::default();
    assert!(!replay_answers_operation(&delete_request(), &response));
}

#[test]
fn replay_never_releases_a_successful_copy_claim() {
    let request: pb::wallet_operation_request::Operation =
        pb::ClaimPresentationCopyRequest::default().into();
    let response = result_response(pb::ClaimPresentationCopyResponse::default().into());
    assert!(!replay_answers_operation(&request, &response));
}
