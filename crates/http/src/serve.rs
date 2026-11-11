// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional Axum adapter for the canonical wallet operation contract.
//!
//! Owns HTTP-only route, content negotiation, body-limit, status, and cache policy.
//! Wallet state, storage, consent, and protocol decisions remain behind generated DTOs.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::decode_wallet_operation_request;
use reallyme_wallet_proto_codec::encode::encode_wallet_operation_response;
use reallyme_wallet_proto_codec::{
    wallet_proto_from_json, wallet_proto_to_json, ProtoErrorReason, MAX_WALLET_PROTO_JSON_BYTES,
};
use reallyme_wallet_runtime::{WalletCoreRuntime, WalletRuntimeBackend};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
const APPLICATION_JSON: &str = "application/json";
const APPLICATION_PROTO: &str = "application/proto";
const BROTLI_ENCODING: &str = "br";
const CACHE_NO_STORE: &str = "no-store";
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_EXECUTIONS: usize = 32;

#[path = "serve_headers.rs"]
mod serve_headers;
#[path = "serve_response.rs"]
mod serve_response;

use serve_headers::header_token_contains;
use serve_response::{canonical_problem_response, response_with_content_type};

/// Axum construction errors for the wallet runtime adapter.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum AxumWalletError {
    /// Request body limit must be positive.
    #[error("invalid_body_limit")]
    InvalidBodyLimit,
    /// Request timeout must be positive and bounded.
    #[error("invalid_request_timeout")]
    InvalidRequestTimeout,
}

/// Injected authentication boundary for the canonical Wallet HTTP route.
pub trait WalletHttpRequestAuthorizer: Send + Sync {
    /// Return true only for requests authenticated by the embedding service.
    fn authorize(&self, headers: &HeaderMap) -> bool;
}

/// Shared Axum state for the canonical WalletCoreService route.
pub struct AxumWalletState<B> {
    runtime: Arc<Mutex<WalletCoreRuntime<B>>>,
    max_body_bytes: usize,
    request_timeout: Duration,
    authorizer: Arc<dyn WalletHttpRequestAuthorizer>,
    execution_slots: Arc<Semaphore>,
}

impl<B> Clone for AxumWalletState<B> {
    fn clone(&self) -> Self {
        Self {
            runtime: Arc::clone(&self.runtime),
            max_body_bytes: self.max_body_bytes,
            request_timeout: self.request_timeout,
            authorizer: Arc::clone(&self.authorizer),
            execution_slots: Arc::clone(&self.execution_slots),
        }
    }
}

impl<B> AxumWalletState<B>
where
    B: WalletRuntimeBackend,
{
    /// Create an Axum state wrapper around an injected wallet backend.
    ///
    /// The adapter supplies no clock of its own. Time-dependent checks use the
    /// backend's trusted clock, so a request cannot carry its own time.
    pub fn new<A>(
        backend: B,
        max_body_bytes: usize,
        request_timeout: Duration,
        authorizer: A,
    ) -> Result<Self, AxumWalletError>
    where
        A: WalletHttpRequestAuthorizer + 'static,
    {
        if max_body_bytes == 0 || max_body_bytes > MAX_WALLET_PROTO_JSON_BYTES {
            return Err(AxumWalletError::InvalidBodyLimit);
        }
        if request_timeout.is_zero() || request_timeout > MAX_REQUEST_TIMEOUT {
            return Err(AxumWalletError::InvalidRequestTimeout);
        }

        Ok(Self {
            runtime: Arc::new(Mutex::new(WalletCoreRuntime::new(backend))),
            max_body_bytes,
            request_timeout,
            authorizer: Arc::new(authorizer),
            execution_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_EXECUTIONS)),
        })
    }

    fn execute(
        &self,
        request: pb::WalletOperationRequest,
    ) -> Result<pb::WalletOperationResponse, ConnectProblem> {
        // A poisoned guard means an injected backend panicked mid-operation and
        // runtime state may be partly applied. Fail closed rather than serve
        // it: in a host that unwinds on panic, every later request returns a
        // server error until the process restarts.
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| ConnectProblem::ServerError)?;
        Ok(runtime.execute_operation(request))
    }
}

/// Create a router exposing only the canonical WalletOperation path.
pub fn wallet_router<B>(state: AxumWalletState<B>) -> Router
where
    B: WalletRuntimeBackend + Send + 'static,
{
    Router::new()
        .route(
            "/reallyme.wallet.v1.WalletCoreService/WalletOperation",
            post(connect_wallet_operation::<B>),
        )
        .with_state(state)
}

/// Default maximum accepted Connect request body size.
#[must_use]
pub const fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

async fn connect_wallet_operation<B>(
    State(state): State<AxumWalletState<B>>,
    request: Request<Body>,
) -> Response
where
    B: WalletRuntimeBackend + Send + 'static,
{
    let response_json = prefers_json(request.headers());
    let response_brotli = accepts_brotli(request.headers());
    if !state.authorizer.authorize(request.headers()) {
        return canonical_problem_response(
            ConnectProblem::Unauthorized,
            response_json,
            response_brotli,
        );
    }
    let connect_request = match tokio::time::timeout(
        state.request_timeout,
        decode_wallet_operation_connect_request(request, state.max_body_bytes),
    )
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(problem)) => {
            return canonical_problem_response(problem, response_json, response_brotli);
        }
        Err(_) => {
            return canonical_problem_response(
                ConnectProblem::RequestTimeout,
                response_json,
                response_brotli,
            );
        }
    };
    let execution_state = state.clone();
    let permit = match Arc::clone(&state.execution_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return canonical_problem_response(
                ConnectProblem::CapacityUnavailable,
                connect_request.prefers_json,
                connect_request.accepts_brotli,
            );
        }
    };
    // Once execution starts it may commit. Keep its permit until completion and
    // await the definitive result so a committed mutation is never reported as
    // an HTTP timeout that invites an unsafe retry.
    let execution = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        execution_state.execute(connect_request.message)
    });
    let execution_result = match execution.await {
        Ok(result) => result,
        Err(_) => Err(ConnectProblem::ServerError),
    };
    match execution_result {
        Ok(message) => match connect_wallet_operation_response(
            StatusCode::OK,
            &message,
            connect_request.prefers_json,
            connect_request.accepts_brotli,
        ) {
            Ok(response) => response,
            Err(problem) => canonical_problem_response(
                problem,
                connect_request.prefers_json,
                connect_request.accepts_brotli,
            ),
        },
        Err(problem) => canonical_problem_response(
            problem,
            connect_request.prefers_json,
            connect_request.accepts_brotli,
        ),
    }
}

struct ConnectRequest {
    message: pb::WalletOperationRequest,
    prefers_json: bool,
    accepts_brotli: bool,
}

async fn decode_wallet_operation_connect_request(
    request: Request<Body>,
    limit: usize,
) -> Result<ConnectRequest, ConnectProblem> {
    let prefers_json = prefers_json(request.headers());
    let accepts_brotli = accepts_brotli(request.headers());
    let request_media_type = request_media_type(request.headers())?;
    let body_encoding = body_encoding(request.headers())?;
    let body = read_body_bytes(request, limit).await?;
    let body = decode_body_bytes(body_encoding, &body, limit)?;
    let message = if body.is_empty() {
        pb::WalletOperationRequest::default()
    } else if matches!(request_media_type, RequestMediaType::Json) {
        let json = core::str::from_utf8(&body)
            .map_err(|_| ConnectProblem::Proto(ProtoErrorReason::InvalidUtf8))?;
        wallet_proto_from_json(json).map_err(|error| ConnectProblem::Proto(error.reason))?
    } else {
        decode_wallet_operation_request(&body)
            .map_err(|error| ConnectProblem::Proto(error.reason))?
    };

    Ok(ConnectRequest {
        message,
        prefers_json,
        accepts_brotli,
    })
}

fn connect_wallet_operation_response(
    status: StatusCode,
    message: &pb::WalletOperationResponse,
    json: bool,
    brotli: bool,
) -> Result<Response, ConnectProblem> {
    if json {
        wallet_proto_to_json(message)
            .map(|body| body.as_bytes().to_vec())
            .map_err(|_| ConnectProblem::SerializationFailed)
            .and_then(|body| maybe_brotli_body(body, brotli))
            .map(|body| response_with_content_type(status, APPLICATION_JSON, brotli, body))
    } else {
        encode_wallet_operation_response(message)
            .map(|body| body.to_vec())
            .map_err(|_| ConnectProblem::SerializationFailed)
            .and_then(|body| maybe_brotli_body(body, brotli))
            .map(|body| response_with_content_type(status, APPLICATION_PROTO, brotli, body))
    }
}

async fn read_body_bytes(
    request: Request<Body>,
    limit: usize,
) -> Result<axum::body::Bytes, ConnectProblem> {
    to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ConnectProblem::PayloadTooLarge)
}

#[derive(Clone, Copy)]
enum ConnectProblem {
    InvalidRequest,
    UnsupportedMediaType,
    Proto(ProtoErrorReason),
    PayloadTooLarge,
    Unauthorized,
    RequestTimeout,
    CapacityUnavailable,
    SerializationFailed,
    ServerError,
}

fn prefers_json(headers: &HeaderMap) -> bool {
    if headers.contains_key(ACCEPT) {
        return header_token_contains(headers, ACCEPT, APPLICATION_JSON);
    }
    matches!(request_media_type(headers), Ok(RequestMediaType::Json))
}

#[derive(Clone, Copy)]
enum RequestMediaType {
    Json,
    Protobuf,
}

fn request_media_type(headers: &HeaderMap) -> Result<RequestMediaType, ConnectProblem> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values.next().ok_or(ConnectProblem::UnsupportedMediaType)?;
    if values.next().is_some() {
        return Err(ConnectProblem::UnsupportedMediaType);
    }
    let value = value
        .to_str()
        .map_err(|_| ConnectProblem::UnsupportedMediaType)?;
    let mut parts = value.split(';');
    let media_type = match parts.next().map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case(APPLICATION_JSON) => RequestMediaType::Json,
        Some(value) if value.eq_ignore_ascii_case(APPLICATION_PROTO) => RequestMediaType::Protobuf,
        _ => return Err(ConnectProblem::UnsupportedMediaType),
    };
    if let Some(parameter) = parts.next() {
        if parts.next().is_some()
            || !matches!(media_type, RequestMediaType::Json)
            || !parameter.trim().eq_ignore_ascii_case("charset=utf-8")
        {
            return Err(ConnectProblem::UnsupportedMediaType);
        }
    }
    Ok(media_type)
}

fn accepts_brotli(headers: &HeaderMap) -> bool {
    headers.get_all(ACCEPT_ENCODING).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|entry| {
                let mut parts = entry.trim().split(';');
                if !parts
                    .next()
                    .is_some_and(|token| token.trim().eq_ignore_ascii_case(BROTLI_ENCODING))
                {
                    return false;
                }
                let mut quality_seen = false;
                for parameter in parts {
                    let Some((name, quality)) = parameter.trim().split_once('=') else {
                        return false;
                    };
                    if !name.trim().eq_ignore_ascii_case("q") || quality_seen {
                        return false;
                    }
                    quality_seen = true;
                    let Ok(weight) = quality.trim().parse::<f32>() else {
                        return false;
                    };
                    if !weight.is_finite() || !(0.0..=1.0).contains(&weight) || weight == 0.0 {
                        return false;
                    }
                }
                true
            })
        })
    })
}

#[derive(Clone, Copy)]
enum BodyEncoding {
    Identity,
    Brotli,
}

fn body_encoding(headers: &HeaderMap) -> Result<BodyEncoding, ConnectProblem> {
    // Accept exactly one coding. A stacked list such as `br, gzip` or a
    // repeated header describes layers this adapter does not decode, so it is
    // refused rather than treated as a single brotli layer.
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(BodyEncoding::Identity);
    };
    if values.next().is_some() {
        return Err(ConnectProblem::InvalidRequest);
    }
    let coding = value
        .to_str()
        .map_err(|_| ConnectProblem::InvalidRequest)?
        .trim();
    if coding.eq_ignore_ascii_case(BROTLI_ENCODING) {
        Ok(BodyEncoding::Brotli)
    } else if coding.eq_ignore_ascii_case("identity") {
        Ok(BodyEncoding::Identity)
    } else {
        Err(ConnectProblem::InvalidRequest)
    }
}

fn decode_body_bytes(
    body_encoding: BodyEncoding,
    body: &[u8],
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ConnectProblem> {
    match body_encoding {
        BodyEncoding::Brotli => compression_brotli::brotli_decompress_with_limit(body, limit)
            .map_err(|error| {
                if error == compression_brotli::BrotliError::OutputTooLarge {
                    ConnectProblem::PayloadTooLarge
                } else {
                    ConnectProblem::InvalidRequest
                }
            }),
        BodyEncoding::Identity => Ok(Zeroizing::new(body.to_vec())),
    }
}

fn maybe_brotli_body(body: Vec<u8>, brotli: bool) -> Result<Vec<u8>, ConnectProblem> {
    if brotli {
        compression_brotli::brotli_compress(&body)
            .map(|compressed| compressed.to_vec())
            .map_err(|_| ConnectProblem::SerializationFailed)
    } else {
        Ok(body)
    }
}
