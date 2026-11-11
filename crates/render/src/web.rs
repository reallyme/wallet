// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded web QR and deep-link delivery helpers.

use reallyme_wallet_types::UnixTimestamp;
use url::Url;
use zeroize::ZeroizeOnDrop;

use crate::{RenderError, RenderErrorReason, RenderResult};

const DEFAULT_MAX_QR_BYTES: usize = 2048;
const DEFAULT_MAX_URL_BYTES: usize = 4096;

/// Size constraints for web delivery payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebDeliveryLimits {
    /// Maximum bytes allowed in a QR payload.
    pub max_qr_bytes: usize,
    /// Maximum bytes allowed in a URL.
    pub max_url_bytes: usize,
}

impl Default for WebDeliveryLimits {
    fn default() -> Self {
        Self {
            max_qr_bytes: DEFAULT_MAX_QR_BYTES,
            max_url_bytes: DEFAULT_MAX_URL_BYTES,
        }
    }
}

/// Payload that can be encoded for web QR delivery.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum WebDeliveryPayload {
    /// Text payload already safe for QR text channels.
    Text(String),
    /// Binary payload to be base64url encoded before QR rendering.
    Bytes(Vec<u8>),
}

/// Web delivery envelope with optional expiry.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WebDeliveryEnvelope {
    /// Payload rendered into the QR handoff.
    pub payload: WebDeliveryPayload,
    /// Expiry timestamp enforced before rendering.
    pub expires_at: Option<UnixTimestamp>,
}

/// QR-safe text payload.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WebQrPayload(String);

impl core::fmt::Debug for WebQrPayload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WebQrPayload(<redacted>)")
    }
}

impl WebQrPayload {
    /// Borrow the QR payload string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Clone the QR payload string for APIs that require owned text.
    #[must_use]
    pub fn to_owned_string(&self) -> String {
        self.0.clone()
    }
}

/// Borrowed query parameter used to construct a deep link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebLinkParam<'a> {
    /// Query parameter name.
    pub name: &'a str,
    /// Query parameter value.
    pub value: &'a str,
}

/// Validated deep-link URL.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WebDeepLink(String);

impl core::fmt::Debug for WebDeepLink {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WebDeepLink(<redacted>)")
    }
}

impl WebDeepLink {
    /// Borrow the deep-link URL string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Clone the deep-link URL string for APIs that require owned text.
    #[must_use]
    pub fn to_owned_string(&self) -> String {
        self.0.clone()
    }
}

/// Build a QR-safe payload from a web delivery envelope.
///
/// Binary payloads are base64url encoded because QR scanners and platform
/// handoff APIs reliably preserve text, not arbitrary bytes.
pub fn build_web_qr(
    envelope: &WebDeliveryEnvelope,
    now: UnixTimestamp,
    limits: WebDeliveryLimits,
) -> RenderResult<WebQrPayload> {
    validate_limits(limits)?;
    enforce_envelope_limits(envelope, now, limits)?;

    let value = match &envelope.payload {
        WebDeliveryPayload::Text(value) => {
            validate_qr_text(value)?;
            value.clone()
        }
        WebDeliveryPayload::Bytes(value) => reallyme_codec::base64url::bytes_to_base64url(value),
    };

    if value.len() > limits.max_qr_bytes {
        return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
    }

    Ok(WebQrPayload(value))
}

/// Build a bounded web deep-link URL with encoded query parameters.
pub fn build_web_deep_link(
    base_url: &str,
    params: &[WebLinkParam<'_>],
    limits: WebDeliveryLimits,
) -> RenderResult<WebDeepLink> {
    validate_limits(limits)?;

    let mut url =
        Url::parse(base_url).map_err(|_| RenderError::new(RenderErrorReason::InvalidUrl))?;
    if !is_supported_scheme(url.scheme()) {
        return Err(RenderError::new(RenderErrorReason::UnsupportedUrlScheme));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str() != base_url
    {
        return Err(RenderError::new(RenderErrorReason::InvalidUrl));
    }
    if base_url.len() > limits.max_url_bytes {
        return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
    }
    for (index, (existing_name, _)) in url.query_pairs().enumerate() {
        if url
            .query_pairs()
            .take(index)
            .any(|(prior_name, _)| prior_name == existing_name)
            || params.iter().any(|param| param.name == existing_name)
        {
            return Err(RenderError::new(RenderErrorReason::InvalidUrl));
        }
    }
    for (index, param) in params.iter().enumerate() {
        if param.name.is_empty() || params[..index].iter().any(|prior| prior.name == param.name) {
            return Err(RenderError::new(RenderErrorReason::InvalidUrl));
        }
        if param.name.len() > limits.max_url_bytes || param.value.len() > limits.max_url_bytes {
            return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
        }
    }

    {
        let mut query = url.query_pairs_mut();
        for param in params {
            query.append_pair(param.name, param.value);
        }
    }

    let value = url.to_string();
    if value.len() > limits.max_url_bytes {
        return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
    }

    Ok(WebDeepLink(value))
}

fn validate_limits(limits: WebDeliveryLimits) -> RenderResult<()> {
    if limits.max_qr_bytes == 0 || limits.max_url_bytes == 0 {
        return Err(RenderError::new(RenderErrorReason::InvalidDeliveryLimits));
    }

    Ok(())
}

fn enforce_envelope_limits(
    envelope: &WebDeliveryEnvelope,
    now: UnixTimestamp,
    limits: WebDeliveryLimits,
) -> RenderResult<()> {
    if let Some(expires_at) = envelope.expires_at {
        if now > expires_at {
            return Err(RenderError::new(RenderErrorReason::ExpiredDelivery));
        }
    }

    let payload_len = match &envelope.payload {
        WebDeliveryPayload::Text(value) => value.len(),
        WebDeliveryPayload::Bytes(value) => value.len(),
    };
    if payload_len > limits.max_qr_bytes {
        return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
    }

    Ok(())
}

/// Reject QR text that a scanner could act on unsafely.
///
/// Control, bidirectional-override, and invisible format characters can
/// disguise the visible text. Leading or trailing whitespace is refused as
/// well, because a scanner that strips it would otherwise see a scheme this
/// check did not. Text that begins with a script, data, local-file, or
/// cleartext `http` scheme is refused; every other text, including wallet
/// schemes such as `openid4vp://` or `mdoc:` and plain text that happens to
/// contain a colon, is accepted.
fn validate_qr_text(value: &str) -> RenderResult<()> {
    let edge_whitespace =
        value.starts_with(char::is_whitespace) || value.ends_with(char::is_whitespace);
    if edge_whitespace
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{00ad}'
                        | '\u{061c}'
                        | '\u{180e}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{2064}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{034f}'
                        | '\u{115f}'
                        | '\u{1160}'
                        | '\u{3164}'
                        | '\u{fe00}'..='\u{fe0f}'
                        | '\u{feff}'
                        | '\u{ffa0}'
                        | '\u{e0000}'..='\u{e007f}'
                        | '\u{e0100}'..='\u{e01ef}'
                )
        })
    {
        return Err(RenderError::new(
            RenderErrorReason::UnsupportedBarcodePayload,
        ));
    }
    if let Some((candidate, _)) = value.split_once(':') {
        let looks_like_scheme = candidate
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
            && candidate.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            });
        if looks_like_scheme && is_refused_qr_scheme(candidate) {
            return Err(RenderError::new(RenderErrorReason::UnsupportedUrlScheme));
        }
    }
    Ok(())
}

/// Schemes a scanner could run, read local data with, or open without TLS.
fn is_refused_qr_scheme(scheme: &str) -> bool {
    [
        "javascript",
        "vbscript",
        "data",
        "file",
        "blob",
        "about",
        "http",
    ]
    .iter()
    .any(|refused| scheme.eq_ignore_ascii_case(refused))
}

fn is_supported_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "https" | "openid-credential-offer" | "openid-vc" | "openid4vp" | "reallyme"
    )
}
