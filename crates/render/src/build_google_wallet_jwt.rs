// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build and check the Google Wallet "Save to Google Wallet" JWT.
//!
//! Wallet constructs the claim set itself so a signer can only sign it. The
//! signer's output must be an RS256 compact JWS whose payload segment is
//! exactly the claims Wallet built.

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_wallet_types::UnixTimestamp;
use serde_json::{json, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::{RenderError, RenderErrorReason, RenderResult};

const GOOGLE_WALLET_AUDIENCE: &str = "google";
const GOOGLE_WALLET_TOKEN_TYPE: &str = "savetowallet";
const GOOGLE_WALLET_SIGNING_ALGORITHM: &str = "RS256";
const MAX_GOOGLE_ISSUER_BYTES: usize = 320;
const MAX_GOOGLE_ORIGINS: usize = 10;
const MAX_GOOGLE_ORIGIN_BYTES: usize = 256;

/// Claims configuration for the Google Wallet save JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleWalletJwtConfig {
    /// Service-account email that signs the JWT (`iss`).
    pub issuer: String,
    /// HTTPS origins allowed to present the save button (`origins`).
    pub origins: Vec<String>,
}

impl GoogleWalletJwtConfig {
    fn validate(&self) -> RenderResult<()> {
        let issuer_valid = !self.issuer.is_empty()
            && self.issuer.len() <= MAX_GOOGLE_ISSUER_BYTES
            && self.issuer.bytes().all(|byte| byte.is_ascii_graphic())
            && self
                .issuer
                .split_once('@')
                .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
        if !issuer_valid || self.origins.len() > MAX_GOOGLE_ORIGINS {
            return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
        }
        for origin in &self.origins {
            let url = Url::parse(origin)
                .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderConfig))?;
            if origin.len() > MAX_GOOGLE_ORIGIN_BYTES
                || url.scheme() != "https"
                || url.host_str().is_none()
                || url.origin().ascii_serialization() != *origin
            {
                return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
            }
        }
        Ok(())
    }
}

/// Serialize the complete claim set for one generic object.
pub(crate) fn google_wallet_claims(
    config: &GoogleWalletJwtConfig,
    generic_object: Value,
    issued_at: UnixTimestamp,
) -> RenderResult<Zeroizing<Vec<u8>>> {
    config.validate()?;
    let claims = json!({
        "iss": config.issuer,
        "aud": GOOGLE_WALLET_AUDIENCE,
        "typ": GOOGLE_WALLET_TOKEN_TYPE,
        "iat": issued_at.as_seconds(),
        "origins": config.origins,
        "payload": { "genericObjects": [generic_object] }
    });
    serde_json::to_vec(&claims)
        .map(Zeroizing::new)
        .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))
}

/// Require an RS256 compact JWS whose payload is exactly `expected_claims`.
pub(crate) fn validate_signed_google_jwt(token: &[u8], expected_claims: &[u8]) -> RenderResult<()> {
    let token = std::str::from_utf8(token)
        .map_err(|_| RenderError::new(RenderErrorReason::SigningFailed))?;
    if !is_compact_jws(token) {
        return Err(RenderError::new(RenderErrorReason::SigningFailed));
    }
    let mut segments = token.split('.');
    let (Some(header), Some(payload)) = (segments.next(), segments.next()) else {
        return Err(RenderError::new(RenderErrorReason::SigningFailed));
    };
    let header = base64url_to_bytes(header)
        .map_err(|_| RenderError::new(RenderErrorReason::SigningFailed))?;
    let header: Value = serde_json::from_slice(&header)
        .map_err(|_| RenderError::new(RenderErrorReason::SigningFailed))?;
    if header.get("alg").and_then(Value::as_str) != Some(GOOGLE_WALLET_SIGNING_ALGORITHM)
        || payload != bytes_to_base64url(expected_claims)
    {
        return Err(RenderError::new(RenderErrorReason::SigningFailed));
    }
    Ok(())
}

/// Return whether `value` is three non-empty base64url segments.
pub(crate) fn is_compact_jws(value: &str) -> bool {
    let mut segments = value.split('.');
    let valid = (0..3).all(|_| {
        segments.next().is_some_and(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    });
    valid && segments.next().is_none()
}
