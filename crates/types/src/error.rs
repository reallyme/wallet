// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet DTO validation.

use thiserror::Error;

/// Error returned when a wallet DTO cannot be constructed safely.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet type validation failed: {reason}")]
pub struct WalletTypesError {
    /// Stable, audit-safe reason code.
    pub reason: WalletTypesErrorReason,
}

impl WalletTypesError {
    /// Build an error from a stable reason.
    #[must_use]
    pub const fn new(reason: WalletTypesErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable reason codes for wallet DTO validation failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WalletTypesErrorReason {
    /// The identifier was empty.
    #[error("empty_identifier")]
    EmptyIdentifier,
    /// The identifier exceeded the bounded audit-safe limit.
    #[error("identifier_too_long")]
    IdentifierTooLong,
    /// The identifier contained characters forbidden by its domain boundary.
    #[error("invalid_identifier")]
    InvalidIdentifier,
    /// An attribute name was empty.
    #[error("empty_attribute_name")]
    EmptyAttributeName,
    /// A timestamp was outside the supported wallet range.
    #[error("timestamp_out_of_range")]
    TimestampOutOfRange,
    /// A distribution card was missing required visible metadata.
    #[error("invalid_distribution_card")]
    InvalidDistributionCard,
    /// A distribution card had too many visible fields.
    #[error("too_many_distribution_fields")]
    TooManyDistributionFields,
    /// A distribution card text field exceeded wallet rendering bounds.
    #[error("distribution_text_too_long")]
    DistributionTextTooLong,
    /// A distribution barcode payload exceeded wallet rendering bounds.
    #[error("distribution_barcode_too_large")]
    DistributionBarcodeTooLarge,
    /// An issuance notification endpoint was not an absolute HTTPS URL.
    #[error("invalid_notification_endpoint")]
    InvalidNotificationEndpoint,
    /// Credential reuse method and reissuance thresholds are inconsistent.
    #[error("invalid_credential_reuse_policy")]
    InvalidCredentialReusePolicy,
}
