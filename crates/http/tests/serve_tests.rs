// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the optional Axum Connect-style wallet runtime adapter.

#![cfg(not(target_arch = "wasm32"))]

use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE, VARY, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, Request, StatusCode};
use buffa::{Message, MessageField};
use reallyme_wallet_http::{
    default_max_body_bytes, wallet_router, AxumWalletError, AxumWalletState,
    WalletHttpRequestAuthorizer,
};
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    credential_record_to_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_proto_codec::{wallet_proto_from_json, wallet_proto_to_json};
use reallyme_wallet_types as wallet;
use tower::ServiceExt;

#[path = "serve/memory_backend.rs"]
mod memory_backend;
use memory_backend::MemoryBackend;

struct AllowTestRequests;
struct DenyTestRequests;

impl WalletHttpRequestAuthorizer for AllowTestRequests {
    fn authorize(&self, _headers: &HeaderMap) -> bool {
        true
    }
}

impl WalletHttpRequestAuthorizer for DenyTestRequests {
    fn authorize(&self, _headers: &HeaderMap) -> bool {
        false
    }
}

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn axum_state_rejects_zero_and_unbounded_body_limits() {
    for limit in [0, usize::MAX] {
        assert!(matches!(
            AxumWalletState::new(
                MemoryBackend::default(),
                limit,
                TEST_TIMEOUT,
                AllowTestRequests,
            ),
            Err(AxumWalletError::InvalidBodyLimit)
        ));
    }
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    timestamp_at(1)
}

fn timestamp_at(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

fn encrypted_record() -> Result<wallet::EncryptedRecord, wallet::WalletTypesError> {
    Ok(wallet::EncryptedRecord {
        header: wallet::EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            algorithm: reallyme_wallet_types::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp()?,
        },
        nonce: vec![1; 12],
        aad: vec![2],
        ciphertext: vec![3; 16],
    })
}

fn credential_record() -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    Ok(wallet::CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        None,
        None,
        None,
        wallet::CredentialFormat::SdJwtVc,
        wallet::CredentialStatus::Active,
        timestamp()?,
        encrypted_record()?,
    ))
}

#[tokio::test]
async fn canonical_connect_rejects_forged_credential_receipt() -> Result<(), RouteTestError> {
    let mut request = pb::WalletOperationRequest::default();
    request.idempotency_key = vec![0xA5; 32];
    request.operation = pb::PutCredentialRecordRequest {
        record: MessageField::some(credential_record_to_proto(&credential_record()?)),
        ..pb::PutCredentialRecordRequest::default()
    }
    .into();
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .body(Body::from(request.encode_to_vec()))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response_bytes(response).await?;
    let message = pb::WalletOperationResponse::decode_from_slice(&bytes)
        .map_err(|_| RouteTestError::Proto)?;
    assert!(matches!(
        message.outcome.as_ref(),
        Some(pb::wallet_operation_response::Outcome::Error(error))
            if error.wallet.as_option().is_some_and(|wallet_error|
                wallet_error.reason.as_known()
                    == Some(pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID))
    ));
    Ok(())
}

#[tokio::test]
async fn committed_mutation_is_not_reported_as_timed_out() -> Result<(), RouteTestError> {
    let request = create_lifecycle_request()?;
    let backend = MemoryBackend {
        commit_delay: Duration::from_millis(150),
        ..MemoryBackend::default()
    };
    let state = AxumWalletState::new(
        backend,
        default_max_body_bytes(),
        Duration::from_millis(50),
        AllowTestRequests,
    )
    .map_err(|_| RouteTestError::State)?;

    let response = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .body(Body::from(request.encode_to_vec()))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn canonical_connect_rejects_unauthorized_requests_before_dispatch(
) -> Result<(), RouteTestError> {
    let state = AxumWalletState::new(
        MemoryBackend::default(),
        default_max_body_bytes(),
        TEST_TIMEOUT,
        DenyTestRequests,
    )
    .map_err(|_| RouteTestError::State)?;
    let response = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .body(Body::from(
                    pb::WalletOperationRequest::default().encode_to_vec(),
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE),
        Some(&axum::http::HeaderValue::from_static("Bearer"))
    );
    Ok(())
}

#[tokio::test]
async fn canonical_connect_brotli_round_trips_typed_envelope() -> Result<(), RouteTestError> {
    let request = pb::WalletOperationRequest::default();
    let body = compression_brotli::brotli_compress(&request.encode_to_vec())
        .map_err(|_| RouteTestError::Compression)?;
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .header(CONTENT_ENCODING, "br")
                .header(ACCEPT_ENCODING, "br")
                .body(Body::from(body.to_vec()))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_ENCODING),
        Some(&axum::http::HeaderValue::from_static("br"))
    );
    let bytes = response_bytes(response).await?;
    let bytes = compression_brotli::brotli_decompress_with_limit(&bytes, default_max_body_bytes())
        .map_err(|_| RouteTestError::Compression)?;
    let message = pb::WalletOperationResponse::decode_from_slice(&bytes)
        .map_err(|_| RouteTestError::Proto)?;
    assert!(matches!(
        message.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(_))
    ));
    Ok(())
}

#[tokio::test]
async fn brotli_zero_quality_is_not_used_and_response_varies_by_negotiation(
) -> Result<(), RouteTestError> {
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .header(ACCEPT_ENCODING, "br;q=0, gzip;q=1")
                .body(Body::from(
                    pb::WalletOperationRequest::default().encode_to_vec(),
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(CONTENT_ENCODING).is_none());
    assert_eq!(
        response.headers().get(VARY),
        Some(&axum::http::HeaderValue::from_static(
            "Accept, Accept-Encoding"
        ))
    );
    Ok(())
}

#[tokio::test]
async fn connect_wallet_operation_returns_domain_error_inside_envelope(
) -> Result<(), RouteTestError> {
    let request = pb::WalletOperationRequest::default();
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .body(Body::from(request.encode_to_vec()))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response_bytes(response).await?;
    let message = pb::WalletOperationResponse::decode_from_slice(&bytes)
        .map_err(|_| RouteTestError::Proto)?;
    assert!(matches!(
        message.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(error))
            if matches!(
                error.wallet.as_option(),
                Some(wallet_error)
                    if wallet_error.reason.as_known()
                        == Some(pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID)
            )
    ));
    Ok(())
}

#[tokio::test]
async fn canonical_connect_json_uses_strict_generated_proto_json() -> Result<(), RouteTestError> {
    let request = pb::WalletOperationRequest::default();
    let request_json = wallet_proto_to_json(&request).map_err(|_| RouteTestError::Proto)?;
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json")
                .body(Body::from(request_json.as_bytes().to_vec()))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response_bytes(response).await?;
    let json = core::str::from_utf8(&bytes).map_err(|_| RouteTestError::Json)?;
    let message = wallet_proto_from_json::<pb::WalletOperationResponse>(json)
        .map_err(|_| RouteTestError::Proto)?;
    assert!(matches!(
        message.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(_))
    ));
    Ok(())
}

#[tokio::test]
async fn protobuf_request_can_negotiate_json_response() -> Result<(), RouteTestError> {
    let request = pb::WalletOperationRequest::default();
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .header(ACCEPT, "application/json")
                .body(Body::from(request.encode_to_vec()))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&axum::http::HeaderValue::from_static("application/json"))
    );
    let bytes = response_bytes(response).await?;
    let json = core::str::from_utf8(&bytes).map_err(|_| RouteTestError::Json)?;
    let message = wallet_proto_from_json::<pb::WalletOperationResponse>(json)
        .map_err(|_| RouteTestError::Proto)?;
    assert!(matches!(
        message.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(_))
    ));
    Ok(())
}

#[path = "serve/boundary.rs"]
mod boundary_tests;

async fn response_bytes(
    response: axum::response::Response,
) -> Result<axum::body::Bytes, RouteTestError> {
    to_bytes(response.into_body(), default_max_body_bytes())
        .await
        .map_err(|_| RouteTestError::Response)
}

fn assert_canonical_proto_error(
    message: &pb::WalletOperationResponse,
    expected_reason: pb::WalletErrorReason,
    expected_detail: pb::ProtoErrorReason,
) {
    assert!(matches!(
        message.outcome.as_ref(),
        Some(pb::wallet_operation_response::Outcome::Error(error))
            if matches!(
                error.wallet.as_option(),
                Some(wallet_error)
                    if wallet_error.reason.as_known() == Some(expected_reason)
                        && matches!(
                            wallet_error.detail.as_ref(),
                            Some(pb::wallet_error::Detail::Proto(detail))
                                if detail.as_known() == Some(expected_detail)
                        )
            )
    ));
}

fn create_lifecycle_request() -> Result<pb::WalletOperationRequest, RouteTestError> {
    let record = lifecycle::new_wallet_lifecycle(id("wallet-unit-1")?, timestamp_at(10)?);
    let mut request = pb::WalletOperationRequest::default();
    request.idempotency_key = vec![0xA5; 32];
    request.operation = pb::PutWalletLifecycleRecordRequest {
        record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
        ..pb::PutWalletLifecycleRecordRequest::default()
    }
    .into();
    Ok(request)
}

#[tokio::test]
async fn poisoned_runtime_lock_fails_closed() -> Result<(), RouteTestError> {
    let backend = MemoryBackend {
        panic_on_begin: true,
        ..MemoryBackend::default()
    };
    let state = AxumWalletState::new(
        backend,
        default_max_body_bytes(),
        TEST_TIMEOUT,
        AllowTestRequests,
    )
    .map_err(|_| RouteTestError::State)?;
    let body = create_lifecycle_request()?.encode_to_vec();
    for _ in 0..2 {
        let response = wallet_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                    .header(CONTENT_TYPE, "application/proto")
                    .body(Body::from(body.clone()))
                    .map_err(|_| RouteTestError::Request)?,
            )
            .await
            .map_err(|_| RouteTestError::Response)?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(())
}

fn state() -> Result<AxumWalletState<MemoryBackend>, RouteTestError> {
    AxumWalletState::new(
        MemoryBackend::default(),
        default_max_body_bytes(),
        TEST_TIMEOUT,
        AllowTestRequests,
    )
    .map_err(|_| RouteTestError::State)
}

#[derive(Debug, thiserror::Error)]
enum RouteTestError {
    #[error("json")]
    Json,
    #[error("proto")]
    Proto,
    #[error("request")]
    Request,
    #[error("response")]
    Response,
    #[error("state")]
    State,
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("compression")]
    Compression,
}
