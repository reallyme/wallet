// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical HTTP success and problem response construction.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, VARY, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::encode::encode_wallet_operation_response;
use reallyme_wallet_proto_codec::{proto_error_to_proto, ProtoErrorReason};
use reallyme_wallet_runtime::{runtime_error_to_proto, wallet_error_envelope, RuntimeErrorReason};

use super::{
    connect_wallet_operation_response, ConnectProblem, APPLICATION_PROTO, BROTLI_ENCODING,
    CACHE_NO_STORE,
};

pub(super) fn canonical_problem_response(
    problem: ConnectProblem,
    json: bool,
    brotli: bool,
) -> Response {
    let (status, wallet_error) = match problem {
        ConnectProblem::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            runtime_error_to_proto(RuntimeErrorReason::InvalidRequest),
        ),
        ConnectProblem::UnsupportedMediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            runtime_error_to_proto(RuntimeErrorReason::InvalidRequest),
        ),
        ConnectProblem::Proto(reason) => (StatusCode::BAD_REQUEST, proto_error_to_proto(reason)),
        ConnectProblem::PayloadTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            proto_error_to_proto(ProtoErrorReason::MessageTooLarge),
        ),
        ConnectProblem::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            runtime_error_to_proto(RuntimeErrorReason::InvalidRequest),
        ),
        ConnectProblem::RequestTimeout => (
            StatusCode::REQUEST_TIMEOUT,
            pb::WalletError {
                reason: pb::WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE.into(),
                ..pb::WalletError::default()
            },
        ),
        ConnectProblem::CapacityUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            pb::WalletError {
                reason: pb::WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE.into(),
                ..pb::WalletError::default()
            },
        ),
        ConnectProblem::SerializationFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            pb::WalletError {
                reason: pb::WalletErrorReason::WALLET_ERROR_REASON_SERIALIZATION_FAILED.into(),
                ..pb::WalletError::default()
            },
        ),
        ConnectProblem::ServerError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            pb::WalletError {
                reason: pb::WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE.into(),
                ..pb::WalletError::default()
            },
        ),
    };
    let message = pb::WalletOperationResponse {
        outcome: Some(pb::wallet_operation_response::Outcome::Error(Box::new(
            wallet_error_envelope(wallet_error),
        ))),
        ..pb::WalletOperationResponse::default()
    };

    let mut response = match connect_wallet_operation_response(status, &message, json, brotli) {
        Ok(response) => response,
        Err(_) => {
            let body = match encode_wallet_operation_response(&message) {
                Ok(encoded) => encoded.to_vec(),
                Err(_) => Vec::new(),
            };
            response_with_content_type(status, APPLICATION_PROTO, false, body)
        }
    };
    if matches!(problem, ConnectProblem::Unauthorized) {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

pub(super) fn response_with_content_type<B>(
    status: StatusCode,
    content_type: &'static str,
    brotli: bool,
    body: B,
) -> Response
where
    B: Into<Body>,
{
    let mut response = (status, body.into()).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(CACHE_NO_STORE));
    headers.insert(VARY, HeaderValue::from_static("Accept, Accept-Encoding"));
    if brotli {
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(BROTLI_ENCODING));
    }
    response
}
