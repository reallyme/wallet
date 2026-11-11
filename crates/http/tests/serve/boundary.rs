// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Malformed and oversized request boundary cases.

use super::{
    assert_canonical_proto_error, response_bytes, state, AllowTestRequests, MemoryBackend,
    RouteTestError, TEST_TIMEOUT,
};
use axum::body::Body;
use axum::http::{
    header::{CONTENT_ENCODING, CONTENT_TYPE},
    Request, StatusCode,
};
use buffa::Message;
use reallyme_wallet_http::{wallet_router, AxumWalletState};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::wallet_proto_from_json;
use tower::ServiceExt;

#[tokio::test]
async fn text_plain_protobuf_body_is_rejected_before_execution() -> Result<(), RouteTestError> {
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(
                    pb::WalletOperationRequest::default().encode_to_vec(),
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    Ok(())
}

#[tokio::test]
async fn canonical_connect_json_rejects_duplicate_keys() -> Result<(), RouteTestError> {
    const DUPLICATE: &str = concat!(
        "{\"getCredentialRecord\":{\"credentialId\":\"one\"},",
        "\"getCredentialRecord\":{\"credentialId\":\"two\"}}"
    );
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(DUPLICATE))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response_bytes(response).await?;
    let json = core::str::from_utf8(&bytes).map_err(|_| RouteTestError::Json)?;
    let message = wallet_proto_from_json::<pb::WalletOperationResponse>(json)
        .map_err(|_| RouteTestError::Proto)?;
    assert_canonical_proto_error(
        &message,
        pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_MALFORMED_WIRE,
        pb::ProtoErrorReason::PROTO_ERROR_REASON_JSON_DUPLICATE_KEY,
    );
    Ok(())
}

#[tokio::test]
async fn canonical_connect_proto_malformed_body_returns_typed_envelope(
) -> Result<(), RouteTestError> {
    let response = wallet_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .body(Body::from(vec![0x0f]))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response_bytes(response).await?;
    let message = pb::WalletOperationResponse::decode_from_slice(&bytes)
        .map_err(|_| RouteTestError::Proto)?;
    assert_canonical_proto_error(
        &message,
        pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_MALFORMED_WIRE,
        pb::ProtoErrorReason::PROTO_ERROR_REASON_MALFORMED_WIRE,
    );
    Ok(())
}

#[tokio::test]
async fn canonical_connect_body_limit_returns_typed_envelope() -> Result<(), RouteTestError> {
    let state = AxumWalletState::new(MemoryBackend::default(), 1, TEST_TIMEOUT, AllowTestRequests)
        .map_err(|_| RouteTestError::State)?;
    let response = wallet_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
                .header(CONTENT_TYPE, "application/proto")
                .body(Body::from(vec![0x12, 0x01, 0x00]))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = response_bytes(response).await?;
    let message = pb::WalletOperationResponse::decode_from_slice(&bytes)
        .map_err(|_| RouteTestError::Proto)?;
    assert_canonical_proto_error(
        &message,
        pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_LIMIT_EXCEEDED,
        pb::ProtoErrorReason::PROTO_ERROR_REASON_MESSAGE_TOO_LARGE,
    );
    Ok(())
}

#[tokio::test]
async fn stacked_or_repeated_content_codings_are_rejected() -> Result<(), RouteTestError> {
    for codings in [vec!["br, gzip"], vec!["br", "br"], vec!["gzip"]] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/reallyme.wallet.v1.WalletCoreService/WalletOperation")
            .header(CONTENT_TYPE, "application/proto");
        for coding in codings {
            builder = builder.header(CONTENT_ENCODING, coding);
        }
        let response = wallet_router(state()?)
            .oneshot(
                builder
                    .body(Body::from(
                        pb::WalletOperationRequest::default().encode_to_vec(),
                    ))
                    .map_err(|_| RouteTestError::Request)?,
            )
            .await
            .map_err(|_| RouteTestError::Response)?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    Ok(())
}
