// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDF conformance wallet harness HTTP adapter.
//!
//! The OIDF suite needs a reachable endpoint it can call to launch wallet
//! flows. This adapter owns the conformance HTTP control plane and requires an
//! injected composed flow driver for protocol completion. The driver is where a
//! higher layer resolves and verifies `request_uri`, selects credentials, builds
//! the DCQL-keyed `vp_token`, encrypts `direct_post.jwt`, and posts the response
//! back to the suite.

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use reallyme_openid4vp_wallet::{
    parse_authorization_request_transport, RequestTransportPolicy, WalletErrorReason,
};
use serde::Serialize;
use zeroize::Zeroizing;

const DEFAULT_HARNESS_MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HARNESS_BODY_BYTES: usize = DEFAULT_HARNESS_MAX_BODY_BYTES;
/// Upper bound on concurrently running composed-driver launches.
const MAX_CONCURRENT_HARNESS_LAUNCHES: usize = 4;
const MAX_BROWSER_API_REQUESTS: usize = 16;
const APPLICATION_JSON: &str = "application/json";
const CACHE_NO_STORE: &str = "no-store";
const PROBLEM_JSON: &str = "application/problem+json";
const TEXT_HTML_UTF8: &str = "text/html; charset=utf-8";
const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const WALLET_ERROR_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>ReallyMe Wallet — Request not accepted</title>
</head>
<body>
<main>
<h1>Request not accepted</h1>
<p>The presentation request could not be verified and was not processed.</p>
<p>No credential information was shared.</p>
</main>
</body>
</html>"#;
const INVALID_REQUEST_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"invalid_request\",\"status\":400,\"error\":\"invalid_request\"}";
const PAYLOAD_TOO_LARGE_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"payload_too_large\",\"status\":413,\"error\":\"payload_too_large\"}";
const NOT_FOUND_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"not_found\",\"status\":404,\"error\":\"not_found\"}";
const UNSUPPORTED_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"unsupported\",\"status\":501,\"error\":\"unsupported\"}";
const CAPACITY_UNAVAILABLE_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"capacity_unavailable\",\"status\":503,\"error\":\"capacity_unavailable\"}";
const SERVER_ERROR_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"server_error\",\"status\":500,\"error\":\"server_error\"}";

/// Construction errors for the OIDF wallet harness.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum OidfWalletHarnessError {
    /// Request body limit must be positive.
    #[error("invalid_body_limit")]
    InvalidBodyLimit,
    /// Callback allowlist entries must be exact URL origins.
    #[error("invalid_callback_origin")]
    InvalidCallbackOrigin,
    /// Control access token does not meet the configured secret length.
    #[error("invalid_control_token")]
    InvalidControlToken,
    /// A host allowlist entry is malformed.
    #[error("invalid_host")]
    InvalidHost,
}

#[path = "oidf_wallet_flow.rs"]
mod oidf_wallet_flow;

pub use oidf_wallet_flow::{
    OidfBrowserApiProtocol, OidfBrowserApiProtocolRequest, OidfBrowserApiRequest,
    OidfWalletFlowDriver, OidfWalletFlowError, OidfWalletFlowErrorReason, OidfWalletFlowRequest,
    OidfWalletFlowStatus,
};

#[path = "oidf_wallet_outcome.rs"]
mod oidf_wallet_outcome;

pub use oidf_wallet_outcome::{
    OidfBrowserHandoff, OidfWalletFlowOutcome, MAX_OIDF_BROWSER_HANDOFF_URI_BYTES,
};

#[path = "parse_oidf_wallet_launch.rs"]
mod parse_oidf_wallet_launch;
use parse_oidf_wallet_launch::{decode_launch_body, DecodedLaunch};

#[path = "strict_json_value.rs"]
mod strict_json_value;

#[path = "oidf_wallet_harness_state.rs"]
mod oidf_wallet_harness_state;

#[path = "check_request_object_callbacks.rs"]
mod check_request_object_callbacks;
use check_request_object_callbacks::request_object_callbacks_allowed;

pub use oidf_wallet_harness_state::OidfWalletHarnessState;
use oidf_wallet_harness_state::{FlowRecord, LaunchStatus};

/// Create a router exposing the OIDF conformance wallet harness.
pub fn oidf_wallet_harness_router(state: OidfWalletHarnessState) -> Router {
    Router::new()
        .route("/healthz", get(handle_health))
        .route(
            "/oidf/wallet/authorize",
            get(handle_authorize_get).post(handle_authorize_post),
        )
        .route("/oidf/wallet/sessions/latest", get(handle_latest))
        .route("/oidf/wallet/error", get(handle_error))
        .route("/oidf/wallet/reset", post(handle_reset))
        .with_state(state)
}

async fn handle_health(
    State(state): State<OidfWalletHarnessState>,
    request: Request<Body>,
) -> Response {
    if !state.allows_host(request.headers()) {
        return problem_response(Problem::InvalidRequest);
    }
    json_message_response(&HealthResponse {
        status: "ok",
        service: "oidf_wallet_harness",
        composed_flow_driver_enabled: state.has_flow_driver(),
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    composed_flow_driver_enabled: bool,
}

async fn handle_authorize_get(
    State(state): State<OidfWalletHarnessState>,
    request: Request<Body>,
) -> Response {
    if !state.allows_host(request.headers()) {
        return problem_response(Problem::InvalidRequest);
    }
    let launch_input = request
        .uri()
        .query()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    handle_launch_input(state, launch_input).await
}

async fn handle_authorize_post(
    State(state): State<OidfWalletHarnessState>,
    request: Request<Body>,
) -> Response {
    if !state.allows_host(request.headers()) {
        return problem_response(Problem::InvalidRequest);
    }
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = match read_body_bytes(request, state.max_body_bytes()).await {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };

    let launch = match decode_launch_body(content_type.as_deref(), &body) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    match launch {
        DecodedLaunch::AuthorizationRequest(launch_input) => {
            handle_launch_input(state, launch_input).await
        }
        DecodedLaunch::BrowserApi {
            request,
            submit_url,
        } => handle_browser_api_launch(state, request, submit_url).await,
    }
}

async fn handle_latest(
    State(state): State<OidfWalletHarnessState>,
    request: Request<Body>,
) -> Response {
    if !state.allows_host(request.headers()) || !state.authorizes_control(request.headers()) {
        return problem_response(Problem::InvalidRequest);
    }
    match state.latest() {
        Ok(Some(record)) => json_message_response(&record),
        Ok(None) => problem_response(Problem::NotFound),
        Err(problem) => problem_response(problem),
    }
}

async fn handle_error(
    State(state): State<OidfWalletHarnessState>,
    request: Request<Body>,
) -> Response {
    if !state.allows_host(request.headers()) {
        return problem_response(Problem::InvalidRequest);
    }
    match state.latest_failure_reason() {
        Ok(Some(_reason)) => html_response(StatusCode::OK, WALLET_ERROR_HTML.as_bytes().to_vec()),
        Ok(None) => problem_response(Problem::NotFound),
        Err(problem) => problem_response(problem),
    }
}

async fn handle_reset(
    State(state): State<OidfWalletHarnessState>,
    request: Request<Body>,
) -> Response {
    if !state.allows_host(request.headers()) || !state.authorizes_control(request.headers()) {
        return problem_response(Problem::InvalidRequest);
    }
    match state.reset() {
        Ok(()) => json_response(StatusCode::NO_CONTENT, Vec::new()),
        Err(problem) => problem_response(problem),
    }
}

async fn handle_launch_input(state: OidfWalletHarnessState, launch_input: String) -> Response {
    // Wipe the request on every early return; ownership moves out only when
    // the composed driver takes it.
    let mut launch_input = Zeroizing::new(launch_input);
    let epoch = match state.launch_epoch() {
        Ok(epoch) => epoch,
        Err(problem) => return problem_response(problem),
    };
    if launch_input.len() > MAX_HARNESS_BODY_BYTES {
        return problem_response(Problem::PayloadTooLarge);
    }
    let transport = match parse_authorization_request_transport(
        &launch_input,
        RequestTransportPolicy::default(),
    ) {
        Ok(value) => value,
        Err(error) => return wallet_problem_response(error.reason()),
    };
    let callbacks_allowed = match &transport {
        reallyme_openid4vp_wallet::AuthorizationRequestTransport::RequestUri { uri, .. } => {
            state.allows_callback_url(uri)
        }
        reallyme_openid4vp_wallet::AuthorizationRequestTransport::RequestJwt { jwt, .. } => {
            request_object_callbacks_allowed(jwt, |uri| state.allows_callback_url(uri))
        }
        // The default policy refuses unsigned inline requests, but check their
        // callbacks too so a policy change cannot skip the allowlist.
        reallyme_openid4vp_wallet::AuthorizationRequestTransport::InlineParams { params } => {
            ["response_uri", "redirect_uri"]
                .iter()
                .filter_map(|name| params.get(*name))
                .all(|uri| state.allows_callback_url(uri))
        }
    };
    if !callbacks_allowed {
        return problem_response(Problem::InvalidRequest);
    }

    let Some(flow_driver) = state.flow_driver() else {
        return match state.record(
            epoch,
            transport,
            LaunchStatus::Unsupported,
            None,
            Some(OidfWalletFlowErrorReason::Unsupported),
        ) {
            Ok(_record) => problem_response(Problem::Unsupported),
            Err(problem) => problem_response(problem),
        };
    };

    let Some(permit) = state.try_reserve_launch() else {
        return problem_response(Problem::CapacityUnavailable);
    };
    let flow_request = OidfWalletFlowRequest::new_authorization_request(
        core::mem::take(&mut *launch_input),
        transport.clone(),
    );
    let flow_outcome = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        flow_driver.drive_oidf_authorization_request(flow_request)
    })
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            return match state.record(
                epoch,
                transport,
                LaunchStatus::Failed,
                None,
                Some(error.reason()),
            ) {
                Ok(_record) => problem_response(Problem::InvalidRequest),
                Err(problem) => problem_response(problem),
            };
        }
        Err(_) => return problem_response(Problem::ServerError),
    };

    match state.record(
        epoch,
        transport,
        LaunchStatus::Completed,
        Some(FlowRecord::from_outcome(flow_outcome)),
        None,
    ) {
        Ok(record) => json_message_response(&record),
        Err(problem) => problem_response(problem),
    }
}

async fn handle_browser_api_launch(
    state: OidfWalletHarnessState,
    request: OidfBrowserApiRequest,
    submit_url: String,
) -> Response {
    let epoch = match state.launch_epoch() {
        Ok(epoch) => epoch,
        Err(problem) => return problem_response(problem),
    };
    if !state.allows_callback_url(&submit_url) {
        return problem_response(Problem::InvalidRequest);
    }
    let request_count = request.requests().len();
    let flow_request = match OidfWalletFlowRequest::from_browser_api(request, submit_url) {
        Ok(value) => value,
        Err(_error) => return problem_response(Problem::InvalidRequest),
    };

    let Some(flow_driver) = state.flow_driver() else {
        return match state.record_browser_api(
            epoch,
            request_count,
            LaunchStatus::Unsupported,
            None,
            Some(OidfWalletFlowErrorReason::Unsupported),
        ) {
            Ok(_record) => problem_response(Problem::Unsupported),
            Err(problem) => problem_response(problem),
        };
    };

    let Some(permit) = state.try_reserve_launch() else {
        return problem_response(Problem::CapacityUnavailable);
    };
    let flow_outcome = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        flow_driver.drive_oidf_authorization_request(flow_request)
    })
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            return match state.record_browser_api(
                epoch,
                request_count,
                LaunchStatus::Failed,
                None,
                Some(error.reason()),
            ) {
                Ok(_record) => problem_response(Problem::InvalidRequest),
                Err(problem) => problem_response(problem),
            };
        }
        Err(_) => return problem_response(Problem::ServerError),
    };

    match state.record_browser_api(
        epoch,
        request_count,
        LaunchStatus::Completed,
        Some(FlowRecord::from_outcome(flow_outcome)),
        None,
    ) {
        Ok(record) => json_message_response(&record),
        Err(problem) => problem_response(problem),
    }
}

async fn read_body_bytes(
    request: Request<Body>,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, Problem> {
    to_bytes(request.into_body(), limit)
        .await
        .map(|body| Zeroizing::new(body.to_vec()))
        .map_err(|_| Problem::PayloadTooLarge)
}

#[derive(Clone, Copy)]
enum Problem {
    InvalidRequest,
    NotFound,
    PayloadTooLarge,
    Unsupported,
    CapacityUnavailable,
    ServerError,
}

fn wallet_problem_response(_reason: WalletErrorReason) -> Response {
    problem_response(Problem::InvalidRequest)
}

fn problem_response(problem: Problem) -> Response {
    match problem {
        Problem::InvalidRequest => problem_body(
            StatusCode::BAD_REQUEST,
            INVALID_REQUEST_BODY.as_bytes().to_vec(),
        ),
        Problem::NotFound => {
            problem_body(StatusCode::NOT_FOUND, NOT_FOUND_BODY.as_bytes().to_vec())
        }
        Problem::PayloadTooLarge => problem_body(
            StatusCode::PAYLOAD_TOO_LARGE,
            PAYLOAD_TOO_LARGE_BODY.as_bytes().to_vec(),
        ),
        Problem::Unsupported => problem_body(
            StatusCode::NOT_IMPLEMENTED,
            UNSUPPORTED_BODY.as_bytes().to_vec(),
        ),
        Problem::CapacityUnavailable => problem_body(
            StatusCode::SERVICE_UNAVAILABLE,
            CAPACITY_UNAVAILABLE_BODY.as_bytes().to_vec(),
        ),
        Problem::ServerError => problem_body(
            StatusCode::INTERNAL_SERVER_ERROR,
            SERVER_ERROR_BODY.as_bytes().to_vec(),
        ),
    }
}

fn json_message_response<M>(message: &M) -> Response
where
    M: Serialize,
{
    match serde_json::to_vec(message) {
        Ok(body) => json_response(StatusCode::OK, body),
        Err(_) => problem_response(Problem::ServerError),
    }
}

fn problem_body(status: StatusCode, body: Vec<u8>) -> Response {
    response_with_content_type(status, PROBLEM_JSON, body)
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
    response_with_content_type(status, APPLICATION_JSON, body)
}

fn html_response(status: StatusCode, body: Vec<u8>) -> Response {
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static(TEXT_HTML_UTF8)),
        (CACHE_CONTROL, HeaderValue::from_static(CACHE_NO_STORE)),
        (
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        ),
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
    ];
    (status, headers, body).into_response()
}

fn response_with_content_type(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response {
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static(content_type)),
        (CACHE_CONTROL, HeaderValue::from_static(CACHE_NO_STORE)),
    ];
    (status, headers, body).into_response()
}

#[cfg(test)]
#[path = "serve_oidf_wallet_harness_tests.rs"]
mod tests;
