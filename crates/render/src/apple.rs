// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Apple Wallet pkpass rendering.

use std::collections::BTreeMap;
use std::io::{self, Write};

use reallyme_wallet_types::{
    DistributionBarcode, DistributionBarcodeFormat, DistributionCard, DistributionField,
    WalletTypesError,
};
use serde::Serialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{RenderError, RenderErrorReason, RenderResult, WalletRenderer};

const MAX_PKPASS_IDENTIFIER_BYTES: usize = 256;
const MAX_PKPASS_ASSETS: usize = 32;
const MAX_PKPASS_ASSET_NAME_BYTES: usize = 128;
const MAX_PKPASS_ASSET_BYTES: usize = 262_144;
const MAX_PKPASS_FILE_BYTES: usize = 1_048_576;
const MAX_PKPASS_IMAGE_PIXELS: u32 = 1_048_576;
/// Decoded-image bound: the pixel cap at 8 bytes per pixel (16-bit RGBA),
/// which covers standard @3x strip and background images.
const MAX_PKPASS_DECODED_IMAGE_BYTES: usize = 8 * 1_048_576;
const MIN_PKPASS_AUTH_TOKEN_BYTES: usize = 16;

#[path = "apple_zip.rs"]
mod apple_zip;

use apple_zip::package_pkpass_zip;

/// Injected detached-signature boundary for PKPass manifests.
pub trait PassSigner {
    /// Sign `manifest.json` bytes with the platform-managed Pass Type ID key.
    fn sign_manifest(&self, manifest_json_bytes: &[u8]) -> RenderResult<Vec<u8>>;
}

/// Minimal configuration required to build `pass.json`.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PkPassConfig {
    /// Apple pass type identifier.
    pub pass_type_identifier: String,
    /// Apple developer team identifier.
    pub team_identifier: String,
    /// Organization display name.
    pub organization_name: String,
    /// Pass description.
    pub description: String,
    /// Unique serial number within the pass type.
    pub serial_number: String,
    /// Optional update web-service URL.
    pub web_service_url: Option<String>,
    /// Optional update authentication token.
    pub authentication_token: Option<String>,
}

impl core::fmt::Debug for PkPassConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PkPassConfig")
            .field("pass_type_identifier", &self.pass_type_identifier)
            .field("team_identifier", &self.team_identifier)
            .field("organization_name", &self.organization_name)
            .field("description", &self.description)
            .field("serial_number", &"<redacted>")
            .field("web_service_url", &self.web_service_url)
            .field(
                "authentication_token",
                &self.authentication_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Renderer that produces `.pkpass` bytes.
pub struct PkPassRenderer<S> {
    config: PkPassConfig,
    signer: S,
    assets: BTreeMap<String, Vec<u8>>,
}

impl<S> PkPassRenderer<S>
where
    S: PassSigner,
{
    /// Create a PKPass renderer.
    #[must_use]
    pub fn new(config: PkPassConfig, signer: S) -> Self {
        Self {
            config,
            signer,
            assets: BTreeMap::new(),
        }
    }

    /// Add a platform image asset such as `icon.png` or `logo.png`.
    pub fn with_asset(mut self, name: String, bytes: Vec<u8>) -> RenderResult<Self> {
        validate_asset(&name, &bytes)?;
        // Pass bundles are unpacked on case-insensitive file systems, so names
        // differing only in case would collide; an exact repeat would silently
        // replace the earlier asset.
        if self.assets.len() >= MAX_PKPASS_ASSETS
            || self
                .assets
                .keys()
                .any(|existing| existing.eq_ignore_ascii_case(&name))
        {
            return Err(RenderError::new(RenderErrorReason::InvalidRenderAsset));
        }
        self.assets.insert(name, bytes);
        Ok(self)
    }

    /// Render `.pkpass` ZIP bytes.
    pub fn render_pkpass(&self, card: &DistributionCard) -> RenderResult<Vec<u8>> {
        validate_config(&self.config)?;
        card.validate().map_err(map_type_error)?;
        if !self.assets.contains_key("icon.png") {
            return Err(RenderError::new(RenderErrorReason::InvalidRenderAsset));
        }
        // Every top-level pass asset is an image, so decode each one, not
        // only the required icon.
        for bytes in self.assets.values() {
            validate_png(bytes)?;
        }

        let pass_json = build_pass_json(&self.config, card)?;
        let mut files = BTreeMap::new();
        files.insert("pass.json".to_owned(), pass_json);
        for (name, bytes) in &self.assets {
            files.insert(name.clone(), Zeroizing::new(bytes.clone()));
        }

        let manifest_json = build_manifest_json(&files)?;
        let signature = self.signer.sign_manifest(&manifest_json)?;
        package_pkpass_zip(&files, &manifest_json, &signature)
    }
}

impl<S> WalletRenderer for PkPassRenderer<S>
where
    S: PassSigner,
{
    fn render_card(&self, card: &DistributionCard) -> RenderResult<Vec<u8>> {
        self.render_pkpass(card)
    }
}

fn validate_config(config: &PkPassConfig) -> RenderResult<()> {
    validate_identifier(&config.pass_type_identifier)?;
    validate_identifier(&config.team_identifier)?;
    validate_identifier(&config.organization_name)?;
    validate_identifier(&config.description)?;
    validate_identifier(&config.serial_number)?;
    match (
        config.web_service_url.as_deref(),
        config.authentication_token.as_deref(),
    ) {
        (None, None) => Ok(()),
        (Some(web_service_url), Some(authentication_token)) => {
            validate_optional_identifier(Some(web_service_url))?;
            validate_optional_identifier(Some(authentication_token))?;
            let parsed = Url::parse(web_service_url)
                .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderConfig))?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
                || parsed.as_str() != web_service_url
                || authentication_token.len() < MIN_PKPASS_AUTH_TOKEN_BYTES
                || !authentication_token
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic())
            {
                return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
            }
            Ok(())
        }
        (Some(_), None) | (None, Some(_)) => {
            Err(RenderError::new(RenderErrorReason::InvalidRenderConfig))
        }
    }
}

fn validate_identifier(value: &str) -> RenderResult<()> {
    if value.is_empty() || value.len() > MAX_PKPASS_IDENTIFIER_BYTES {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
    }

    Ok(())
}

fn validate_optional_identifier(value: Option<&str>) -> RenderResult<()> {
    if let Some(value) = value {
        if value.len() > MAX_PKPASS_IDENTIFIER_BYTES {
            return Err(RenderError::new(RenderErrorReason::InvalidRenderConfig));
        }
    }

    Ok(())
}

fn validate_asset(name: &str, bytes: &[u8]) -> RenderResult<()> {
    // Pass images use plain lowercase names such as `logo@2x.png`, and Wallet
    // looks them up exactly. Limiting names to this set keeps separators,
    // control characters, and `:` out of the ZIP.
    let normalized_name = name.to_ascii_lowercase();
    if name.is_empty()
        || name.len() > MAX_PKPASS_ASSET_NAME_BYTES
        || bytes.is_empty()
        || bytes.len() > MAX_PKPASS_ASSET_BYTES
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'@' | b'.' | b'-' | b'_')
        })
        || name.starts_with('.')
        || name.contains("..")
        || !normalized_name.ends_with(".png")
    {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderAsset));
    }

    Ok(())
}

fn validate_png(bytes: &[u8]) -> RenderResult<()> {
    let mut decoder = png::Decoder::new_with_limits(
        std::io::Cursor::new(bytes),
        png::Limits {
            bytes: MAX_PKPASS_DECODED_IMAGE_BYTES,
        },
    );
    decoder.set_ignore_text_chunk(true);
    let mut reader = decoder
        .read_info()
        .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderAsset))?;
    let info = reader.info();
    let pixel_count = info
        .width
        .checked_mul(info.height)
        .ok_or(RenderError::new(RenderErrorReason::InvalidRenderAsset))?;
    if pixel_count == 0 || pixel_count > MAX_PKPASS_IMAGE_PIXELS || info.is_animated() {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderAsset));
    }
    let output_size = reader
        .output_buffer_size()
        .ok_or(RenderError::new(RenderErrorReason::InvalidRenderAsset))?;
    if output_size > MAX_PKPASS_DECODED_IMAGE_BYTES {
        return Err(RenderError::new(RenderErrorReason::InvalidRenderAsset));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderAsset))?;
    output.resize(output_size, 0);
    reader
        .next_frame(&mut output)
        .and_then(|_| reader.finish())
        .map_err(|_| RenderError::new(RenderErrorReason::InvalidRenderAsset))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplePassJson<'a> {
    format_version: u8,
    pass_type_identifier: &'a str,
    team_identifier: &'a str,
    organization_name: &'a str,
    description: &'a str,
    serial_number: &'a str,
    logo_text: &'a str,
    generic: AppleGeneric<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_service_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration_date: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    barcode: Option<&'a AppleBarcode<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    barcodes: Option<&'a [AppleBarcode<'a>]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppleGeneric<'a> {
    primary_fields: Vec<AppleField<'a>>,
    secondary_fields: Vec<AppleField<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    auxiliary_fields: Vec<AppleField<'a>>,
}

#[derive(Serialize)]
struct AppleField<'a> {
    key: String,
    label: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppleBarcode<'a> {
    format: &'static str,
    message: &'a str,
    message_encoding: &'static str,
}

struct BoundedPassJsonWriter {
    bytes: Zeroizing<Vec<u8>>,
}

impl BoundedPassJsonWriter {
    fn new() -> RenderResult<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        // Reserve before any personal data is serialized. Subsequent writes
        // cannot reallocate and leave an earlier plaintext copy behind.
        bytes
            .try_reserve_exact(MAX_PKPASS_FILE_BYTES)
            .map_err(|_| RenderError::new(RenderErrorReason::PayloadTooLarge))?;
        Ok(Self { bytes })
    }

    fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut *self.bytes))
    }
}

impl Write for BoundedPassJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_length = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or(io::Error::from(io::ErrorKind::OutOfMemory))?;
        if next_length > MAX_PKPASS_FILE_BYTES {
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn build_pass_json(
    config: &PkPassConfig,
    card: &DistributionCard,
) -> RenderResult<Zeroizing<Vec<u8>>> {
    let (primary_fields, secondary_fields) = split_fields(&card.fields);
    let auxiliary_fields = card.subtitle.as_ref().map_or_else(Vec::new, |subtitle| {
        vec![AppleField {
            key: String::from("subtitle"),
            label: "Subtitle",
            value: subtitle,
        }]
    });
    let expiration_date = card
        .valid_until
        .map(|valid_until| {
            OffsetDateTime::from_unix_timestamp(valid_until.as_seconds())
                .map_err(|_| RenderError::new(RenderErrorReason::InvalidDistributionCard))?
                .format(&Rfc3339)
                .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))
        })
        .transpose()?;
    let barcode = card.barcode.as_ref().map(map_barcode).transpose()?;
    let pass = ApplePassJson {
        format_version: 1,
        pass_type_identifier: &config.pass_type_identifier,
        team_identifier: &config.team_identifier,
        organization_name: &config.organization_name,
        description: &config.description,
        serial_number: &config.serial_number,
        logo_text: &card.title,
        generic: AppleGeneric {
            primary_fields,
            secondary_fields,
            auxiliary_fields,
        },
        web_service_url: config.web_service_url.as_deref(),
        authentication_token: config.authentication_token.as_deref(),
        expiration_date: expiration_date.as_deref(),
        barcode: barcode.as_ref(),
        barcodes: barcode.as_ref().map(std::slice::from_ref),
    };
    let mut writer = BoundedPassJsonWriter::new()?;
    serde_json::to_writer(&mut writer, &pass)
        .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))?;
    Ok(writer.into_bytes())
}

fn split_fields(fields: &[DistributionField]) -> (Vec<AppleField<'_>>, Vec<AppleField<'_>>) {
    let mut primary = Vec::new();
    let mut secondary = Vec::new();

    for (index, field) in fields.iter().enumerate() {
        let mut key = String::from("field_");
        key.push_str(&index.to_string());
        let object = AppleField {
            key,
            label: &field.label,
            value: &field.value,
        };
        if field.emphasized && primary.len() < 2 {
            primary.push(object);
        } else {
            secondary.push(object);
        }
    }

    (primary, secondary)
}

fn map_barcode(barcode: &DistributionBarcode) -> RenderResult<AppleBarcode<'_>> {
    let message = std::str::from_utf8(&barcode.payload)
        .map_err(|_| RenderError::new(RenderErrorReason::UnsupportedBarcodePayload))?;
    let format = match barcode.format {
        DistributionBarcodeFormat::Qr => "PKBarcodeFormatQR",
        DistributionBarcodeFormat::Pdf417 => "PKBarcodeFormatPDF417",
        DistributionBarcodeFormat::Aztec => "PKBarcodeFormatAztec",
        DistributionBarcodeFormat::Code128 => "PKBarcodeFormatCode128",
    };

    Ok(AppleBarcode {
        format,
        message,
        message_encoding: "utf-8",
    })
}

fn build_manifest_json(files: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> RenderResult<Vec<u8>> {
    let mut manifest = serde_json::Map::new();
    for (name, bytes) in files {
        if bytes.len() > MAX_PKPASS_FILE_BYTES {
            return Err(RenderError::new(RenderErrorReason::PayloadTooLarge));
        }
        let digest = Sha1::digest(bytes.as_slice());
        manifest.insert(name.clone(), Value::String(hex_lower(digest.as_slice())));
    }

    serde_json::to_vec(&Value::Object(manifest))
        .map_err(|_| RenderError::new(RenderErrorReason::SerializationFailed))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn map_type_error(_error: WalletTypesError) -> RenderError {
    RenderError::new(RenderErrorReason::InvalidDistributionCard)
}
