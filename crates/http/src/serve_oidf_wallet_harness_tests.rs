// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use axum::body::to_bytes;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const TEST_CONTROL_TOKEN: &str = "test-control-token-with-at-least-thirty-two-bytes";

use super::oidf_wallet_harness_state::{LaunchRecord, TransportRecord};
use super::parse_oidf_wallet_launch::LaunchRequestBody;
use super::{handle_launch_input, MAX_CONCURRENT_HARNESS_LAUNCHES, MAX_HARNESS_BODY_BYTES};
use crate::{
    oidf_wallet_harness_router, OidfWalletFlowDriver, OidfWalletFlowError,
    OidfWalletFlowErrorReason, OidfWalletFlowOutcome, OidfWalletFlowRequest,
    OidfWalletHarnessError, OidfWalletHarnessState,
};

#[derive(Clone, Copy)]
enum TestFlowDriver {
    Succeed,
    SucceedWithBrowserHandoff,
    Fail,
}

impl OidfWalletFlowDriver for TestFlowDriver {
    fn drive_oidf_authorization_request(
        &self,
        request: OidfWalletFlowRequest,
    ) -> Result<OidfWalletFlowOutcome, OidfWalletFlowError> {
        assert_eq!(format!("{request:?}"), "OidfWalletFlowRequest(<redacted>)");
        match self {
            Self::Succeed | Self::SucceedWithBrowserHandoff => {
                if let Some(launch_input) = request.authorization_request_input() {
                    assert!(!launch_input.is_empty());
                    assert!(request.authorization_request_transport().is_some());
                    let browser_handoff = match self {
                        Self::SucceedWithBrowserHandoff => Some(
                            crate::OidfBrowserHandoff::parse(
                                "https://suite.example/callback#one-time-secret".to_owned(),
                            )
                            .expect("test handoff is valid"),
                        ),
                        Self::Succeed | Self::Fail => None,
                    };
                    return Ok(OidfWalletFlowOutcome::direct_post_jwt_submitted(
                        browser_handoff,
                    ));
                }
                assert_eq!(
                    request
                        .browser_api_request()
                        .map(|value| value.requests().len()),
                    Some(1)
                );
                assert!(request.browser_api_submit_url().is_some());
                Ok(OidfWalletFlowOutcome::dc_api_jwt_submitted())
            }
            Self::Fail => Err(OidfWalletFlowError::new(
                OidfWalletFlowErrorReason::RequestVerificationFailed,
            )),
        }
    }
}

#[test]
fn browser_handoff_requires_bounded_https_without_userinfo() {
    for invalid in [
        "",
        "http://suite.example/callback",
        "https://user@suite.example/callback",
        "relative/callback",
    ] {
        assert!(crate::OidfBrowserHandoff::parse(invalid.to_owned()).is_err());
    }
    let oversized = format!(
        "https://suite.example/{}",
        "a".repeat(crate::MAX_OIDF_BROWSER_HANDOFF_URI_BYTES)
    );
    assert!(crate::OidfBrowserHandoff::parse(oversized).is_err());
    let valid = crate::OidfBrowserHandoff::parse(
        "https://suite.example/callback#one-time-secret".to_owned(),
    )
    .expect("HTTPS handoff with a fragment is valid");
    assert_eq!(format!("{valid:?}"), "OidfBrowserHandoff(<redacted>)");
}

#[tokio::test]
async fn returns_browser_handoff_for_front_channel_navigation() {
    let app = oidf_wallet_harness_router(allowed_state(OidfWalletHarnessState::with_flow_driver(
        TestFlowDriver::SucceedWithBrowserHandoff,
    )));
    let request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request=e30.e30.c2ln")
        .body(Body::empty())
        .expect("request builds");

    let response = app.clone().oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("response body is bounded");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("response is valid JSON");
    assert_eq!(
        payload["flow"]["redirect_uri"],
        "https://suite.example/callback#one-time-secret"
    );
    let latest = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .header("Authorization", format!("Bearer {TEST_CONTROL_TOKEN}"))
        .uri("/oidf/wallet/sessions/latest")
        .body(Body::empty())
        .expect("request builds");
    let latest_response = app.oneshot(latest).await.expect("latest route responds");
    assert_eq!(latest_response.status(), StatusCode::OK);
    let latest_body = to_bytes(latest_response.into_body(), 4096)
        .await
        .expect("latest body is bounded");
    let latest_payload: serde_json::Value =
        serde_json::from_slice(&latest_body).expect("latest body is valid JSON");
    assert!(latest_payload["flow"].get("redirect_uri").is_none());
}

#[test]
fn oidf_launch_owners_advertise_drop_time_zeroization() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<OidfWalletFlowRequest>();
    assert_zeroize_on_drop::<LaunchRequestBody>();
    assert_zeroize_on_drop::<LaunchRecord>();
    assert_zeroize_on_drop::<TransportRecord>();
}

#[test]
fn harness_state_rejects_zero_and_unbounded_body_limits() {
    for limit in [0, usize::MAX] {
        assert!(matches!(
            OidfWalletHarnessState::with_max_body_bytes(limit),
            Err(OidfWalletHarnessError::InvalidBodyLimit)
        ));
        assert!(matches!(
            OidfWalletHarnessState::with_max_body_bytes_and_flow_driver(
                limit,
                TestFlowDriver::Succeed,
            ),
            Err(OidfWalletHarnessError::InvalidBodyLimit)
        ));
    }
}

fn driven_state() -> OidfWalletHarnessState {
    allowed_state(OidfWalletHarnessState::with_flow_driver(
        TestFlowDriver::Succeed,
    ))
}

fn allowed_state(state: OidfWalletHarnessState) -> OidfWalletHarnessState {
    state
        .with_allowed_callback_origins(&[
            "https://verifier.example",
            "https://suite.example",
            "http://127.0.0.1:8443",
        ])
        .expect("test callback origins are valid")
        .with_control_token(Zeroizing::new(TEST_CONTROL_TOKEN.to_owned()))
        .expect("test control token is valid")
}

#[tokio::test]
async fn health_reports_composed_driver_state() {
    for (state, expected) in [
        (OidfWalletHarnessState::new(), false),
        (driven_state(), true),
    ] {
        let request = Request::builder()
            .method("GET")
            .header("Host", "127.0.0.1:8787")
            .uri("/healthz")
            .body(Body::empty())
            .expect("request builds");

        let response = oidf_wallet_harness_router(state)
            .oneshot(request)
            .await
            .expect("health route responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("health body is bounded");
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("health body is valid JSON");
        assert_eq!(payload["composed_flow_driver_enabled"], expected);
    }
}

#[tokio::test]
async fn accepts_post_request_uri_launch() {
    let app = oidf_wallet_harness_router(driven_state());
    let request = Request::builder()
        .method("POST")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{
                    "client_id":"x509_san_dns:verifier.example",
                    "request_uri":"https://verifier.example/request.jwt",
                    "request_uri_method":"post"
                }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn accepts_valid_browser_api_launch() {
    let app = oidf_wallet_harness_router(driven_state());
    let request = Request::builder()
        .method("POST")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{
                "browser_api_request": {
                    "digital": {
                        "requests": [{
                            "protocol": "openid4vp-v1-signed",
                            "data": {"request": "e30.e30.c2ln"}
                        }]
                    }
                },
                "submit_url": "https://suite.example/browser/submit"
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn accepts_loopback_http_browser_api_callback_for_local_suite() {
    let app = oidf_wallet_harness_router(driven_state());
    let request = Request::builder()
        .method("POST")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{
                "browser_api_request": {
                    "digital": {
                        "requests": [{
                            "protocol": "openid4vp-v1-signed",
                            "data": {"request": "e30.e30.c2ln"}
                        }]
                    }
                },
                "submit_url": "http://127.0.0.1:8443/browser/submit"
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_mixed_or_unsafe_browser_api_launch() {
    for body in [
        r#"{
            "authorization_request": "request=e30.e30.c2ln",
            "browser_api_request": {
                "digital": {"requests": [{
                    "protocol": "openid4vp-v1-signed",
                    "data": {"request": "e30.e30.c2ln"}
                }]}
            },
            "submit_url": "https://suite.example/browser/submit"
        }"#,
        r#"{
            "browser_api_request": {
                "digital": {"requests": [{
                    "protocol": "openid4vp-v1-signed",
                    "data": {"request": "e30.e30.c2ln"}
                }]}
            },
            "submit_url": "http://suite.example/browser/submit"
        }"#,
        r#"{
            "browser_api_request": {
                "digital": {"requests": [{
                    "protocol": "openid4vp-v1-signed",
                    "data": {"request": "e30.e30.c2ln"}
                }]}
            },
            "submit_url": "https://user:password@suite.example/browser/submit"
        }"#,
    ] {
        let request = Request::builder()
            .method("POST")
            .header("Host", "127.0.0.1:8787")
            .uri("/oidf/wallet/authorize")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("request builds");

        let response = oidf_wallet_harness_router(driven_state())
            .oneshot(request)
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn rejects_duplicate_unknown_and_wrong_shape_launch_json() {
    for body in [
        r#"{"request_uri":"https://one.example","request_uri":"https://two.example"}"#,
        r#"{"request_uri":"https://verifier.example","unknown":true}"#,
        r#"{"request_uri":{"nested":"https://verifier.example"}}"#,
        r#"{
            "browser_api_request": {
                "digital": {"requests": [{
                    "protocol": "openid4vp-v1-signed",
                    "data": {
                        "request": "e30.e30.c2ln",
                        "request": "e30.e30.b3RoZXI"
                    }
                }]}
            },
            "submit_url": "https://suite.example/browser/submit"
        }"#,
    ] {
        let request = Request::builder()
            .method("POST")
            .header("Host", "127.0.0.1:8787")
            .uri("/oidf/wallet/authorize")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("request builds");

        let response = oidf_wallet_harness_router(driven_state())
            .oneshot(request)
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn rejects_oversized_get_launch_input() {
    let oversized_length = MAX_HARNESS_BODY_BYTES
        .checked_add(1)
        .unwrap_or(MAX_HARNESS_BODY_BYTES);
    let response = handle_launch_input(driven_state(), "a".repeat(oversized_length)).await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn rejects_launch_when_composed_driver_is_missing() {
    let app = oidf_wallet_harness_router(allowed_state(OidfWalletHarnessState::new()));
    let request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn records_failed_composed_driver_result() {
    let app = oidf_wallet_harness_router(allowed_state(OidfWalletHarnessState::with_flow_driver(
        TestFlowDriver::Fail,
    )));
    let request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");

    let response = app.clone().oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let latest = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .header("Authorization", format!("Bearer {TEST_CONTROL_TOKEN}"))
        .uri("/oidf/wallet/sessions/latest")
        .body(Body::empty())
        .expect("request builds");

    let latest_response = app.oneshot(latest).await.expect("latest route responds");

    assert_eq!(latest_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn exposes_a_non_sensitive_error_view_only_after_a_typed_flow_failure() {
    let empty_app = oidf_wallet_harness_router(driven_state());
    let empty_request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/error")
        .body(Body::empty())
        .expect("request builds");
    let empty_response = empty_app
        .oneshot(empty_request)
        .await
        .expect("error route responds");
    assert_eq!(empty_response.status(), StatusCode::NOT_FOUND);

    let app = oidf_wallet_harness_router(allowed_state(OidfWalletHarnessState::with_flow_driver(
        TestFlowDriver::Fail,
    )));
    let launch = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");
    let launch_response = app.clone().oneshot(launch).await.expect("route responds");
    assert_eq!(launch_response.status(), StatusCode::BAD_REQUEST);

    let error_request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/error")
        .body(Body::empty())
        .expect("request builds");
    let error_response = app
        .oneshot(error_request)
        .await
        .expect("error route responds");
    assert_eq!(error_response.status(), StatusCode::OK);
    assert_eq!(
        error_response.headers().get(CONTENT_TYPE),
        Some(&"text/html; charset=utf-8".parse().expect("header parses"))
    );
    let body = to_bytes(error_response.into_body(), 4096)
        .await
        .expect("error body is bounded");
    let html = core::str::from_utf8(&body).expect("error body is UTF-8");
    assert!(html.contains("Request not accepted"));
    assert!(!html.contains("request.jwt"));
    assert!(!html.contains("request_verification_failed"));
}

#[tokio::test]
async fn exposes_latest_launch_session() {
    let app = oidf_wallet_harness_router(driven_state());
    let request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");
    app.clone()
        .oneshot(request)
        .await
        .expect("launch route responds");
    let latest = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .header("Authorization", format!("Bearer {TEST_CONTROL_TOKEN}"))
        .uri("/oidf/wallet/sessions/latest")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(latest).await.expect("latest route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_invalid_wallet_nonce_for_get_request_uri() {
    let app = oidf_wallet_harness_router(OidfWalletHarnessState::new());
    let request = Request::builder()
            .method("GET")
        .header("Host", "127.0.0.1:8787")
            .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt&wallet_nonce=nonce")
            .body(Body::empty())
            .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refuses_every_callback_when_no_callback_origins_are_configured() {
    let state = OidfWalletHarnessState::new()
        .with_control_token(Zeroizing::new(TEST_CONTROL_TOKEN.to_owned()))
        .expect("test control token is valid");
    let app = oidf_wallet_harness_router(state);
    let request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_request_uri_outside_callback_origin_allowlist() {
    let app = oidf_wallet_harness_router(driven_state());
    let request = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fattacker.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reset_clears_latest_launch_session() {
    let app = oidf_wallet_harness_router(driven_state());
    let launch = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .uri("/oidf/wallet/authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt")
        .body(Body::empty())
        .expect("request builds");
    app.clone()
        .oneshot(launch)
        .await
        .expect("launch route responds");
    let reset = Request::builder()
        .method("POST")
        .header("Host", "127.0.0.1:8787")
        .header("Authorization", format!("Bearer {TEST_CONTROL_TOKEN}"))
        .uri("/oidf/wallet/reset")
        .body(Body::empty())
        .expect("request builds");
    app.clone()
        .oneshot(reset)
        .await
        .expect("reset route responds");
    let latest = Request::builder()
        .method("GET")
        .header("Host", "127.0.0.1:8787")
        .header("Authorization", format!("Bearer {TEST_CONTROL_TOKEN}"))
        .uri("/oidf/wallet/sessions/latest")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(latest).await.expect("latest route responds");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn control_routes_reject_missing_or_wrong_authorization_and_host() {
    let app = oidf_wallet_harness_router(driven_state());
    for (host, authorization) in [
        ("127.0.0.1:8787", None),
        (
            "127.0.0.1:8787",
            Some("Bearer wrong-control-token-with-at-least-thirty-two-bytes"),
        ),
        (
            "attacker.example",
            Some("Bearer test-control-token-with-at-least-thirty-two-bytes"),
        ),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .header("Host", host)
            .uri("/oidf/wallet/reset");
        if let Some(value) = authorization {
            builder = builder.header("Authorization", value);
        }
        let request = builder.body(Body::empty()).expect("request builds");
        let response = app.clone().oneshot(request).await.expect("route responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let launch = Request::builder()
        .method("GET")
        .header("Host", "attacker.example")
        .uri("/oidf/wallet/authorize?request=e30.e30.c2ln")
        .body(Body::empty())
        .expect("request builds");
    let response = app.oneshot(launch).await.expect("route responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn launches_beyond_the_concurrency_bound_are_refused() {
    let state = driven_state();
    let held: Vec<_> = (0..MAX_CONCURRENT_HARNESS_LAUNCHES)
        .map(|_| state.try_reserve_launch().expect("launch slot is free"))
        .collect();

    let refused = handle_launch_input(state.clone(), "request=e30.e30.c2ln".to_owned()).await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);

    drop(held);
    let accepted = handle_launch_input(state, "request=e30.e30.c2ln".to_owned()).await;
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[test]
fn authorization_request_launch_rejects_sibling_parameters() {
    let body = serde_json::to_vec(&serde_json::json!({
        "authorization_request": "request=e30.e30.c2ln",
        "client_id": "x509_san_dns:other.example"
    }))
    .expect("launch body serializes");
    assert!(
        super::parse_oidf_wallet_launch::decode_launch_body(Some("application/json"), &body)
            .is_err()
    );
}

#[test]
fn reset_during_an_inflight_launch_stays_effective() {
    use super::oidf_wallet_harness_state::LaunchStatus;

    let state = driven_state();
    let before_reset = state.launch_epoch().ok().expect("epoch is readable");
    state.reset().ok().expect("reset succeeds");
    state
        .record_browser_api(before_reset, 1, LaunchStatus::Completed, None, None)
        .ok()
        .expect("late record still answers its caller");
    assert!(state.latest().ok().expect("latest is readable").is_none());

    let after_reset = state.launch_epoch().ok().expect("epoch is readable");
    state
        .record_browser_api(after_reset, 1, LaunchStatus::Completed, None, None)
        .ok()
        .expect("current record is stored");
    assert!(state.latest().ok().expect("latest is readable").is_some());
}

#[test]
fn host_and_control_token_checks_are_exact() {
    use axum::http::header::{AUTHORIZATION, HOST};
    use axum::http::{HeaderMap, HeaderValue};

    let state = driven_state();
    let host = |value: &'static str| {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static(value));
        state.allows_host(&headers)
    };
    assert!(host("127.0.0.1:8787"));
    for rejected in [
        "127.0.0.1:8788",
        "127.0.0.1",
        "127.0.0.1:8787.",
        "localhost:8787",
    ] {
        assert!(!host(rejected));
    }
    let mut repeated = HeaderMap::new();
    repeated.append(HOST, HeaderValue::from_static("127.0.0.1:8787"));
    repeated.append(HOST, HeaderValue::from_static("127.0.0.1:8787"));
    assert!(!state.allows_host(&repeated));

    let control = |value: String| {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&value).expect("valid header"),
        );
        state.authorizes_control(&headers)
    };
    assert!(control(format!("Bearer {TEST_CONTROL_TOKEN}")));
    assert!(control(format!("bearer {TEST_CONTROL_TOKEN}")));
    assert!(!control(format!("Basic {TEST_CONTROL_TOKEN}")));
    assert!(!control(format!("Bearer {TEST_CONTROL_TOKEN}x")));
    assert!(!control("Bearer short".to_owned()));
}

#[tokio::test]
async fn by_value_request_object_callbacks_must_be_allowlisted() {
    let refused = handle_launch_input(
        driven_state(),
        "request=e30.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2F0dGFja2VyLmV4YW1wbGUvY2IifQ.c2ln"
            .to_owned(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let accepted = handle_launch_input(
        driven_state(),
        "request=e30.eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUvY2IifQ.c2ln"
            .to_owned(),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);

    // A duplicated callback key is refused even when the last value is allowed.
    let duplicated = handle_launch_input(
        driven_state(),
        "request=e30.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2F0dGFja2VyLmV4YW1wbGUvY2IiLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUvY2IifQ.c2ln".to_owned(),
    )
    .await;
    assert_eq!(duplicated.status(), StatusCode::BAD_REQUEST);
}
