// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated Wallet distribution-card domain values.
//!
//! Renderers consume these values directly. They deliberately do not implement
//! Serde and cannot become a second external DTO contract beside Wallet
//! protobuf and generated ProtoJSON.

use crate::{UnixTimestamp, WalletTypesError, WalletTypesErrorReason};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_DISTRIBUTION_TEXT_BYTES: usize = 512;
const MAX_DISTRIBUTION_FIELDS: usize = 32;
const MAX_DISTRIBUTION_BARCODE_BYTES: usize = 4096;

/// Human-facing card rendered into platform wallet artifacts.
///
/// This is a rendering target derived from verified wallet state. It is not a
/// credential and must not become the source of truth for identity attributes.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct DistributionCard {
    /// Primary visible title.
    pub title: String,
    /// Optional secondary visible label.
    pub subtitle: Option<String>,
    /// Issuer display label after trust and policy processing.
    pub issuer: String,
    /// Optional expiration timestamp.
    pub valid_until: Option<UnixTimestamp>,
    /// User-visible rows.
    pub fields: Vec<DistributionField>,
    /// Optional machine-readable barcode payload.
    pub barcode: Option<DistributionBarcode>,
    /// Optional verification link.
    pub verification_uri: Option<String>,
}

impl DistributionCard {
    /// Validate bounds shared by platform renderers.
    pub fn validate(&self) -> Result<(), WalletTypesError> {
        validate_required_text(&self.title)?;
        validate_required_text(&self.issuer)?;
        validate_optional_text(self.subtitle.as_deref())?;
        validate_optional_text(self.verification_uri.as_deref())?;
        if let Some(uri) = self.verification_uri.as_deref() {
            validate_verification_uri(uri)?;
        }

        if self.fields.len() > MAX_DISTRIBUTION_FIELDS {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::TooManyDistributionFields,
            ));
        }
        for field in &self.fields {
            field.validate()?;
        }
        if let Some(barcode) = &self.barcode {
            barcode.validate()?;
        }

        Ok(())
    }
}

/// One visible distribution field.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct DistributionField {
    /// Visible field label.
    pub label: String,
    /// Visible field value.
    pub value: String,
    /// Whether a platform renderer should emphasize this field.
    pub emphasized: bool,
}

impl DistributionField {
    fn validate(&self) -> Result<(), WalletTypesError> {
        validate_required_text(&self.label)?;
        validate_required_text(&self.value)
    }
}

/// Machine-readable barcode payload.
#[derive(Clone, PartialEq, Eq)]
pub struct DistributionBarcode {
    /// Barcode format hint.
    pub format: DistributionBarcodeFormat,
    /// Raw payload. Platform renderers may require UTF-8.
    pub payload: Vec<u8>,
}

impl Zeroize for DistributionBarcode {
    fn zeroize(&mut self) {
        self.payload.zeroize();
    }
}

impl Drop for DistributionBarcode {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DistributionBarcode {}

impl DistributionBarcode {
    fn validate(&self) -> Result<(), WalletTypesError> {
        if self.payload.is_empty() || self.payload.len() > MAX_DISTRIBUTION_BARCODE_BYTES {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::DistributionBarcodeTooLarge,
            ));
        }
        // Code 128 encodes only the ASCII range.
        if self.format == DistributionBarcodeFormat::Code128 && !self.payload.is_ascii() {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidDistributionCard,
            ));
        }

        Ok(())
    }
}

/// Supported platform barcode formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionBarcodeFormat {
    /// QR code.
    Qr,
    /// PDF417 barcode.
    Pdf417,
    /// Aztec barcode.
    Aztec,
    /// Code 128 barcode.
    Code128,
}

fn validate_required_text(value: &str) -> Result<(), WalletTypesError> {
    if value.is_empty() {
        return Err(WalletTypesError::new(
            WalletTypesErrorReason::InvalidDistributionCard,
        ));
    }

    validate_text_bound(value)
}

fn validate_optional_text(value: Option<&str>) -> Result<(), WalletTypesError> {
    if let Some(value) = value {
        validate_text_bound(value)?;
    }

    Ok(())
}

/// A verification link must be an absolute HTTPS URL with a host and no
/// embedded credentials, so a card cannot carry `javascript:`, `data:`, or
/// plaintext links.
fn validate_verification_uri(value: &str) -> Result<(), WalletTypesError> {
    let url = url::Url::parse(value)
        .map_err(|_| WalletTypesError::new(WalletTypesErrorReason::InvalidDistributionCard))?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(WalletTypesError::new(
            WalletTypesErrorReason::InvalidDistributionCard,
        ));
    }
    Ok(())
}

fn validate_text_bound(value: &str) -> Result<(), WalletTypesError> {
    if value.len() > MAX_DISTRIBUTION_TEXT_BYTES {
        return Err(WalletTypesError::new(
            WalletTypesErrorReason::DistributionTextTooLong,
        ));
    }

    if value.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
    }) {
        return Err(WalletTypesError::new(
            WalletTypesErrorReason::InvalidDistributionCard,
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "distribution_tests.rs"]
mod tests;
