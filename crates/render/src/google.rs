// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Google Wallet generic-object rendering.

use reallyme_wallet_types::{
    DistributionBarcode, DistributionBarcodeFormat, DistributionCard, UnixTimestamp,
    WalletTypesError,
};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use zeroize::ZeroizeOnDrop;

use crate::build_google_wallet_jwt::{
    google_wallet_claims, validate_signed_google_jwt, GoogleWalletJwtConfig,
};
use crate::{RenderError, RenderErrorReason, RenderResult, WalletRenderer};

const MAX_GOOGLE_IDENTIFIER_BYTES: usize = 256;
const MAX_GOOGLE_TEXT_MODULES: usize = 10;
const DEFAULT_GOOGLE_SAVE_URL_PREFIX: &str = "https://pay.google.com/gp/v/save/";
const DEFAULT_MAX_GOOGLE_SAVE_URL_BYTES: usize = 4096;

/// Injected signing boundary for Google Wallet JWT transport.
pub trait GoogleWalletSigner {
    /// Sign the serialized Google Wallet claim set.
    ///
    /// Return an RS256 compact JWS whose payload segment is exactly
    /// `payload_json`, base64url-encoded. Any other output, including a JWS
    /// over re-serialized or modified claims, is refused.
    fn sign_payload(&self, payload_json: &[u8]) -> RenderResult<Vec<u8>>;
}

/// Trusted time source used to classify a rendered object's current state.
pub trait GoogleWalletClock {
    /// Return the current time from the host's trusted clock boundary.
    fn now(&self) -> RenderResult<UnixTimestamp>;
}

/// Configuration for a Google Wallet generic object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleWalletConfig {
    /// Google issuer id.
    pub issuer_id: String,
    /// Issuer-owned generic class id.
    pub class_id: String,
    /// Issuer-owned object id.
    pub object_id: String,
}

/// Configuration for Google Wallet Save URL generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleWalletSaveConfig {
    /// Google save URL prefix.
    pub save_url_prefix: String,
    /// Maximum URL bytes accepted by the caller.
    pub max_url_bytes: usize,
}

impl Default for GoogleWalletSaveConfig {
    fn default() -> Self {
        Self {
            save_url_prefix: DEFAULT_GOOGLE_SAVE_URL_PREFIX.to_owned(),
            max_url_bytes: DEFAULT_MAX_GOOGLE_SAVE_URL_BYTES,
        }
    }
}

/// Bounded Google Wallet save URL.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct GoogleWalletSaveLink(String);

impl core::fmt::Debug for GoogleWalletSaveLink {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("GoogleWalletSaveLink(<redacted>)")
    }
}

impl GoogleWalletSaveLink {
    /// Borrow the save URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Clone the save URL for APIs that require ownership.
    #[must_use]
    pub fn to_owned_string(&self) -> String {
        self.0.clone()
    }
}

/// Renderer for Google Wallet generic-object JSON or an injected signed payload.
pub struct GoogleWalletRenderer<S, C> {
    config: GoogleWalletConfig,
    signer: Option<(S, GoogleWalletJwtConfig)>,
    clock: C,
}

impl<S, C> GoogleWalletRenderer<S, C>
where
    S: GoogleWalletSigner,
    C: GoogleWalletClock,
{
    /// Create a renderer that returns raw object JSON.
    #[must_use]
    pub const fn new(config: GoogleWalletConfig, clock: C) -> Self {
        Self {
            config,
            signer: None,
            clock,
        }
    }

    /// Create a renderer that returns a signed save JWT.
    ///
    /// Wallet builds the claim set from `jwt`; the signer only signs it.
    #[must_use]
    pub fn with_signer(mut self, signer: S, jwt: GoogleWalletJwtConfig) -> Self {
        self.signer = Some((signer, jwt));
        self
    }

    /// Render the Google Wallet object JSON.
    pub fn render_object_json(&self, card: &DistributionCard) -> RenderResult<Vec<u8>> {
        let (object, _now) = self.render_object_value(card)?;
        serde_json::to_vec(&object)
            .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))
    }

    fn render_object_value(&self, card: &DistributionCard) -> RenderResult<(Value, UnixTimestamp)> {
        validate_config(&self.config)?;
        card.validate().map_err(map_type_error)?;
        let now = self.clock.now()?;
        if card.fields.len() > MAX_GOOGLE_TEXT_MODULES {
            return Err(RenderError::new(RenderErrorReason::InvalidDistributionCard));
        }
        if let Some(uri) = card.verification_uri.as_deref() {
            let parsed = Url::parse(uri)
                .map_err(|_| RenderError::new(RenderErrorReason::InvalidDistributionCard))?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
                || parsed.as_str() != uri
            {
                return Err(RenderError::new(RenderErrorReason::InvalidDistributionCard));
            }
        }

        let object_id = join_google_id(&self.config.issuer_id, &self.config.object_id)?;
        let class_id = join_google_id(&self.config.issuer_id, &self.config.class_id)?;
        let subtitle = card
            .subtitle
            .as_deref()
            .unwrap_or(card.issuer.as_str())
            .to_owned();

        let rows = card
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                json!({
                    "id": index.to_string(),
                    "header": field.label,
                    "body": field.value
                })
            })
            .collect::<Vec<Value>>();

        let state = if card.valid_until.is_some_and(|end| now > end) {
            "EXPIRED"
        } else {
            "ACTIVE"
        };
        let mut object = json!({
            "id": object_id,
            "classId": class_id,
            "state": state,
            "genericType": "GENERIC_TYPE_UNSPECIFIED",
            "cardTitle": {
                "defaultValue": {
                    "language": "en",
                    "value": card.title
                }
            },
            "subheader": {
                "defaultValue": {
                    "language": "en",
                    "value": subtitle
                }
            },
            "header": {
                "defaultValue": {
                    "language": "en",
                    "value": card.title
                }
            },
            "textModulesData": rows
        });

        if let Some(barcode) = &card.barcode {
            object["barcode"] = map_barcode(barcode)?;
        }
        if let Some(uri) = &card.verification_uri {
            object["linksModuleData"] = json!({
                "uris": [
                    {
                        "uri": uri,
                        "description": "Verify"
                    }
                ]
            });
        }
        if let Some(valid_until) = card.valid_until {
            let date = OffsetDateTime::from_unix_timestamp(valid_until.as_seconds())
                .map_err(|_| RenderError::new(RenderErrorReason::InvalidDistributionCard))?
                .format(&Rfc3339)
                .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))?;
            object["validTimeInterval"] = json!({"end": {"date": date}});
        }

        Ok((object, now))
    }

    /// Render a signed save JWT and fail closed when no signer is configured.
    ///
    /// The signer's output must be an RS256 compact JWS over exactly the claim
    /// set built here: `iss`, `aud`, `typ`, `iat`, `origins`, and the object.
    pub fn render_signed_or_raw(&self, card: &DistributionCard) -> RenderResult<Vec<u8>> {
        let Some((signer, jwt)) = &self.signer else {
            return Err(RenderError::new(RenderErrorReason::SignerRequired));
        };
        let (object, now) = self.render_object_value(card)?;
        let claims = google_wallet_claims(jwt, object, now)?;
        let token = signer.sign_payload(&claims)?;
        validate_signed_google_jwt(&token, &claims)?;
        Ok(token)
    }
}

impl<S, C> WalletRenderer for GoogleWalletRenderer<S, C>
where
    S: GoogleWalletSigner,
    C: GoogleWalletClock,
{
    fn render_card(&self, card: &DistributionCard) -> RenderResult<Vec<u8>> {
        self.render_signed_or_raw(card)
    }
}

fn validate_config(config: &GoogleWalletConfig) -> RenderResult<()> {
    if config.issuer_id.is_empty() || !config.issuer_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
    }
    validate_identifier(&config.class_id)?;
    validate_identifier(&config.object_id)
}

/// Build a bounded Google Wallet Save URL from an injected signer.
///
/// `payload_json` is the complete claim set to sign. The helper validates the
/// save URL prefix, requires the signer to return an RS256 compact JWS over
/// exactly those claims, and enforces the caller's URL length bound.
pub fn build_google_wallet_save_link(
    payload_json: &[u8],
    signer: &dyn GoogleWalletSigner,
    config: &GoogleWalletSaveConfig,
) -> RenderResult<GoogleWalletSaveLink> {
    validate_save_config(config)?;
    if payload_json.is_empty() || payload_json.len() > config.max_url_bytes {
        return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
    }

    let jwt_bytes = signer.sign_payload(payload_json)?;
    // The token is appended to the save URL path. Accept only an RS256 compact
    // JWS over exactly `payload_json`, so signer output cannot add `?`, `#`,
    // or `/`, reshape the URL, or substitute other claims.
    validate_signed_google_jwt(&jwt_bytes, payload_json)?;
    let jwt = std::str::from_utf8(&jwt_bytes)
        .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))?;
    let capacity = config
        .save_url_prefix
        .len()
        .checked_add(jwt.len())
        .ok_or(RenderError::new(RenderErrorReason::PayloadTooLarge))?;
    if capacity > config.max_url_bytes {
        return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
    }

    let mut url = String::with_capacity(capacity);
    url.push_str(&config.save_url_prefix);
    url.push_str(jwt);

    Ok(GoogleWalletSaveLink(url))
}

fn validate_save_config(config: &GoogleWalletSaveConfig) -> RenderResult<()> {
    if config.save_url_prefix.is_empty() || config.max_url_bytes == 0 {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
    }
    let url = Url::parse(&config.save_url_prefix)
        .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderConfig))?;
    if url.scheme() != "https" {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
    }

    Ok(())
}

fn validate_identifier(value: &str) -> RenderResult<()> {
    if value.is_empty()
        || value.len() > MAX_GOOGLE_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || value.contains("..")
    {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
    }

    Ok(())
}

fn join_google_id(issuer_id: &str, object_id: &str) -> RenderResult<String> {
    let capacity = issuer_id
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(object_id.len()))
        .ok_or(RenderError::new(RenderErrorReason::PayloadTooLarge))?;
    let mut value = String::with_capacity(capacity);
    value.push_str(issuer_id);
    value.push('.');
    value.push_str(object_id);
    Ok(value)
}

fn map_barcode(barcode: &DistributionBarcode) -> RenderResult<Value> {
    let value = std::str::from_utf8(&barcode.payload)
        .map_err(|_| RenderError::new(RenderErrorReason::UnsupportedBarcodePayload))?;
    let kind = match barcode.format {
        DistributionBarcodeFormat::Qr => "QR_CODE",
        DistributionBarcodeFormat::Pdf417 => "PDF_417",
        DistributionBarcodeFormat::Aztec => "AZTEC",
        DistributionBarcodeFormat::Code128 => "CODE_128",
    };

    Ok(json!({
        "type": kind,
        "value": value,
        "alternateText": "Verify"
    }))
}

fn map_type_error(_error: WalletTypesError) -> RenderError {
    RenderError::new(RenderErrorReason::InvalidDistributionCard)
}
