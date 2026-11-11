// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet render operations.

use thiserror::Error;

/// Result type for render operations.
pub type RenderResult<T> = Result<T, RenderError>;

/// Typed render error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet render operation failed: {reason}")]
pub struct RenderError {
    /// Stable reason code.
    pub reason: RenderErrorReason,
}

impl RenderError {
    /// Construct a render error from a stable reason.
    #[must_use]
    pub const fn new(reason: RenderErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable render failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RenderErrorReason {
    /// A distribution format requires a configured signing backend.
    #[error("signer_required")]
    SignerRequired,
    /// Requested render target is disabled or unsupported.
    #[error("unsupported_render_target")]
    UnsupportedRenderTarget,
    /// Delivery payload expired before rendering.
    #[error("expired_delivery")]
    ExpiredDelivery,
    /// Delivery payload or generated URL exceeded configured bounds.
    #[error("payload_too_large")]
    PayloadTooLarge,
    /// Configured delivery limits are not usable.
    #[error("invalid_delivery_limits")]
    InvalidDeliveryLimits,
    /// Deep-link base URL could not be parsed.
    #[error("invalid_url")]
    InvalidUrl,
    /// Deep-link URL uses a scheme this wallet surface does not support.
    #[error("unsupported_url_scheme")]
    UnsupportedUrlScheme,
    /// Distribution card failed shared wallet-card validation.
    #[error("invalid_distribution_card")]
    InvalidDistributionCard,
    /// Platform render configuration is incomplete or out of bounds.
    #[error("invalid_render_config")]
    InvalidRenderConfig,
    /// Platform asset name or bytes are not accepted.
    #[error("invalid_render_asset")]
    InvalidRenderAsset,
    /// Platform renderer requires a UTF-8 barcode payload.
    #[error("unsupported_barcode_payload")]
    UnsupportedBarcodePayload,
    /// Platform signing boundary failed.
    #[error("signing_failed")]
    SigningFailed,
    /// Platform artifact packaging failed.
    #[error("packaging_failed")]
    PackagingFailed,
    /// Platform artifact serialization failed.
    #[error("serialization_failed")]
    SerializationFailed,
}
