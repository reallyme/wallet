// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic issuance completion and notification outbox records.

use core::fmt;

use crate::{
    NonEmptyIdentifier, SignedCredentialIssuer, UnixTimestamp, WalletTypesError,
    WalletTypesErrorReason,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Required byte length of an issuance idempotency key and request digest.
pub const OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES: usize = 32;
/// Maximum encoded notification endpoint length retained for retry.
pub const MAX_NOTIFICATION_ENDPOINT_BYTES: usize = 4_096;

/// Validated, bounded notification endpoint retained by the durable outbox.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct OpenId4VciNotificationEndpoint(String);

impl OpenId4VciNotificationEndpoint {
    /// Construct a bounded endpoint after protocol-layer URL validation.
    pub fn new(value: String, credential_issuer: &str) -> Result<Self, WalletTypesError> {
        if value.len() > MAX_NOTIFICATION_ENDPOINT_BYTES {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::IdentifierTooLong,
            ));
        }
        let parsed = url::Url::parse(&value).map_err(|_| {
            WalletTypesError::new(WalletTypesErrorReason::InvalidNotificationEndpoint)
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str() != value
        {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidNotificationEndpoint,
            ));
        }
        let issuer = url::Url::parse(credential_issuer).map_err(|_| {
            WalletTypesError::new(WalletTypesErrorReason::InvalidNotificationEndpoint)
        })?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || issuer.origin() != parsed.origin()
        {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidNotificationEndpoint,
            ));
        }
        Ok(Self(value))
    }

    /// Borrow the endpoint without copying it into another long-lived owner.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for OpenId4VciNotificationEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenId4VciNotificationEndpoint(<redacted>)")
    }
}

/// Durable notification delivery stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum OpenId4VciNotificationDeliveryState {
    /// The credential import committed and delivery remains retryable.
    Pending,
    /// The issuer accepted the notification; retries must stop.
    Delivered,
}

/// Durable outbox entry that carries only an opaque secure-token handle.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct OpenId4VciNotificationOutboxEntry {
    /// Credential Issuer origin authenticated for this issuance session.
    pub credential_issuer: SignedCredentialIssuer,
    /// Issuer-provided notification identifier.
    pub notification_id: NonEmptyIdentifier,
    /// Validated notification endpoint.
    pub notification_endpoint: OpenId4VciNotificationEndpoint,
    /// Opaque handle resolved by the secure access-token provider.
    pub access_token_binding_handle: NonEmptyIdentifier,
    /// Current delivery stage.
    pub delivery_state: OpenId4VciNotificationDeliveryState,
    /// Number of completed delivery attempts.
    pub delivery_attempts: u32,
    /// Time of the last durable outbox transition.
    pub updated_at: UnixTimestamp,
}

#[cfg(test)]
#[path = "issuance_tests.rs"]
mod tests;
