// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for bounded web QR and deep-link helpers.

use reallyme_wallet_render::{
    build_web_deep_link, build_web_qr, RenderErrorReason, WebDeliveryEnvelope, WebDeliveryLimits,
    WebDeliveryPayload, WebLinkParam,
};
use reallyme_wallet_types::{UnixTimestamp, WalletTypesError};

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn default_limits() -> WebDeliveryLimits {
    WebDeliveryLimits::default()
}

#[test]
fn qr_text_payload_is_returned_unchanged() -> Result<(), TestError> {
    let envelope = WebDeliveryEnvelope {
        payload: WebDeliveryPayload::Text("openid4vp://request".to_owned()),
        expires_at: Some(timestamp(20)?),
    };

    let payload = build_web_qr(&envelope, timestamp(10)?, default_limits())?;

    assert_eq!(payload.as_str(), "openid4vp://request");
    Ok(())
}

#[test]
fn qr_binary_payload_is_base64url_encoded() -> Result<(), TestError> {
    let envelope = WebDeliveryEnvelope {
        payload: WebDeliveryPayload::Bytes(vec![1, 2, 3]),
        expires_at: None,
    };

    let payload = build_web_qr(&envelope, timestamp(10)?, default_limits())?;

    assert_eq!(payload.as_str(), "AQID");
    Ok(())
}

#[test]
fn qr_rejects_expired_payload() -> Result<(), TestError> {
    let envelope = WebDeliveryEnvelope {
        payload: WebDeliveryPayload::Text("present".to_owned()),
        expires_at: Some(timestamp(9)?),
    };

    let result = build_web_qr(&envelope, timestamp(10)?, default_limits());

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::ExpiredDelivery
    ));
    Ok(())
}

#[test]
fn qr_rejects_payload_larger_than_qr_limit_before_encoding() -> Result<(), TestError> {
    let envelope = WebDeliveryEnvelope {
        payload: WebDeliveryPayload::Text("abcd".to_owned()),
        expires_at: None,
    };
    let limits = WebDeliveryLimits {
        max_qr_bytes: 3,
        max_url_bytes: 64,
    };

    let result = build_web_qr(&envelope, timestamp(10)?, limits);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::PayloadTooLarge
    ));
    Ok(())
}

#[test]
fn qr_rejects_binary_payload_larger_than_qr_limit_after_encoding() -> Result<(), TestError> {
    let envelope = WebDeliveryEnvelope {
        payload: WebDeliveryPayload::Bytes(vec![1, 2, 3]),
        expires_at: None,
    };
    let limits = WebDeliveryLimits {
        max_qr_bytes: 3,
        max_url_bytes: 64,
    };

    let result = build_web_qr(&envelope, timestamp(10)?, limits);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::PayloadTooLarge
    ));
    Ok(())
}

#[test]
fn deep_link_builds_https_url_with_encoded_query() -> Result<(), TestError> {
    let params = [
        WebLinkParam {
            name: "payload",
            value: "a b",
        },
        WebLinkParam {
            name: "state",
            value: "x/y",
        },
    ];

    let link = build_web_deep_link("https://wallet.example/import", &params, default_limits())?;

    assert_eq!(
        link.as_str(),
        "https://wallet.example/import?payload=a+b&state=x%2Fy"
    );
    Ok(())
}

#[test]
fn deep_link_allows_wallet_specific_schemes() -> Result<(), TestError> {
    let params = [WebLinkParam {
        name: "request_uri",
        value: "https://verifier.example/request.jwt",
    }];

    let link = build_web_deep_link("openid4vp://authorize", &params, default_limits())?;

    assert_eq!(
        link.as_str(),
        "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt"
    );
    Ok(())
}

#[test]
fn deep_link_rejects_unsupported_scheme() {
    let result = build_web_deep_link(
        "javascript:alert(1)",
        &[WebLinkParam {
            name: "payload",
            value: "x",
        }],
        default_limits(),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::UnsupportedUrlScheme
    ));
}

#[test]
fn deep_link_rejects_invalid_url() {
    let result = build_web_deep_link(
        "not a url",
        &[WebLinkParam {
            name: "payload",
            value: "x",
        }],
        default_limits(),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::InvalidUrl
    ));
}

#[test]
fn deep_link_rejects_userinfo_fragment_and_duplicate_parameters() {
    for base in [
        "https://user@wallet.example/import",
        "https://wallet.example/import#secret",
        "https://wallet.example/import?state=one&state=two",
        "https://wallet.example/import?state=one",
    ] {
        assert!(matches!(
            build_web_deep_link(
                base,
                &[WebLinkParam { name: "state", value: "three" }],
                default_limits(),
            ),
            Err(error) if error.reason == RenderErrorReason::InvalidUrl
        ));
    }
    assert!(matches!(
        build_web_deep_link(
            "https://wallet.example/import",
            &[
                WebLinkParam { name: "state", value: "one" },
                WebLinkParam { name: "state", value: "two" },
            ],
            default_limits(),
        ),
        Err(error) if error.reason == RenderErrorReason::InvalidUrl
    ));
}

#[test]
fn deep_link_rejects_url_larger_than_limit() {
    let limits = WebDeliveryLimits {
        max_qr_bytes: 64,
        max_url_bytes: 20,
    };
    let result = build_web_deep_link(
        "https://wallet.example/import",
        &[WebLinkParam {
            name: "payload",
            value: "abcdefghijklmnopqrstuvwxyz",
        }],
        limits,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::PayloadTooLarge
    ));
}

#[test]
fn web_delivery_rejects_zero_limits() -> Result<(), TestError> {
    let envelope = WebDeliveryEnvelope {
        payload: WebDeliveryPayload::Text("present".to_owned()),
        expires_at: None,
    };
    let limits = WebDeliveryLimits {
        max_qr_bytes: 0,
        max_url_bytes: 64,
    };

    let result = build_web_qr(&envelope, timestamp(10)?, limits);

    assert!(matches!(
        result,
        Err(error) if error.reason == RenderErrorReason::InvalidDeliveryLimits
    ));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("render")]
    Render(#[from] reallyme_wallet_render::RenderError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}

#[test]
fn qr_rejects_unsafe_schemes_and_hidden_characters() -> Result<(), TestError> {
    for (text, reason) in [
        (
            "javascript:alert(1)",
            RenderErrorReason::UnsupportedUrlScheme,
        ),
        ("DATA:text/html,x", RenderErrorReason::UnsupportedUrlScheme),
        (
            "http://wallet.example",
            RenderErrorReason::UnsupportedUrlScheme,
        ),
        (
            "pay\u{202e}lpmaxe",
            RenderErrorReason::UnsupportedBarcodePayload,
        ),
        ("line\nbreak", RenderErrorReason::UnsupportedBarcodePayload),
        (
            " javascript:alert(1)",
            RenderErrorReason::UnsupportedBarcodePayload,
        ),
        (
            "\u{00a0}javascript:alert(1)",
            RenderErrorReason::UnsupportedBarcodePayload,
        ),
        (
            "\u{200b}data:text/html,x",
            RenderErrorReason::UnsupportedBarcodePayload,
        ),
        (
            "java\u{feff}script:alert(1)",
            RenderErrorReason::UnsupportedBarcodePayload,
        ),
        (
            "java\u{e0041}script:alert(1)",
            RenderErrorReason::UnsupportedBarcodePayload,
        ),
        ("vbscript:msgbox", RenderErrorReason::UnsupportedUrlScheme),
        (
            "FILE:///etc/passwd",
            RenderErrorReason::UnsupportedUrlScheme,
        ),
    ] {
        let envelope = WebDeliveryEnvelope {
            payload: WebDeliveryPayload::Text(text.to_owned()),
            expires_at: Some(timestamp(20)?),
        };
        assert!(matches!(
            build_web_qr(&envelope, timestamp(10)?, default_limits()),
            Err(error) if error.reason == reason
        ));
    }
    for text in [
        "https://wallet.example/import",
        "ABC-123",
        "openid-credential-offer://?x=1",
        "two words",
        "Ref:42",
        "urn:uuid:4f5a2c1e-0000-4000-8000-000000000001",
        "mdoc:owBjMS4wAYIB2BhYS6Q",
        "haip-vp://?request_uri=https%3A%2F%2Fverifier.example%2Fr",
    ] {
        let envelope = WebDeliveryEnvelope {
            payload: WebDeliveryPayload::Text(text.to_owned()),
            expires_at: Some(timestamp(20)?),
        };
        assert_eq!(
            build_web_qr(&envelope, timestamp(10)?, default_limits())?.as_str(),
            text
        );
    }
    Ok(())
}
