// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable wallet state for credential reuse and reissuance policy.
//!
//! Policy copies accompany authenticated CAS snapshots. Each owns and wipes its
//! identifier; policy data alone never grants a credential-use capability.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NonEmptyIdentifier, WalletTypesError, WalletTypesErrorReason};

/// Reuse method the wallet selected from authenticated issuer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum CredentialReuseMethod {
    /// No profile-specific reuse restriction applies.
    Unrestricted,
    /// Each credential instance may be presented once.
    OnceOnly,
    /// Reuse is bounded by remaining credential lifetime.
    LimitedTime,
    /// The wallet rotates through a credential batch.
    RotatingBatch,
    /// The wallet uses a stable credential instance per relying party.
    PerRelyingParty,
}

/// Validated durable selection for one credential configuration.
#[derive(Clone, Eq, PartialEq, ZeroizeOnDrop)]
pub struct CredentialReusePolicySelection {
    credential_configuration_id: NonEmptyIdentifier,
    method: CredentialReuseMethod,
    batch_size: Option<u32>,
    reissue_trigger_unused: Option<u32>,
    reissue_trigger_lifetime_left_seconds: Option<u64>,
}

impl CredentialReusePolicySelection {
    /// Construct a selection after validating method-specific invariants.
    pub fn new(
        credential_configuration_id: NonEmptyIdentifier,
        method: CredentialReuseMethod,
        batch_size: Option<u32>,
        reissue_trigger_unused: Option<u32>,
        reissue_trigger_lifetime_left_seconds: Option<u64>,
    ) -> Result<Self, WalletTypesError> {
        let valid = match method {
            CredentialReuseMethod::Unrestricted => {
                batch_size.is_none()
                    && reissue_trigger_unused.is_none()
                    && reissue_trigger_lifetime_left_seconds.is_none()
            }
            CredentialReuseMethod::OnceOnly => matches!(
                (batch_size, reissue_trigger_unused),
                (Some(size), Some(unused)) if size >= 2 && unused < size
            ),
            CredentialReuseMethod::LimitedTime => reissue_trigger_lifetime_left_seconds.is_some(),
            CredentialReuseMethod::RotatingBatch | CredentialReuseMethod::PerRelyingParty => {
                batch_size.is_some_and(|size| size >= 2)
                    && reissue_trigger_lifetime_left_seconds.is_some()
            }
        };
        if !valid {
            return Err(WalletTypesError::new(
                WalletTypesErrorReason::InvalidCredentialReusePolicy,
            ));
        }
        Ok(Self {
            credential_configuration_id,
            method,
            batch_size,
            reissue_trigger_unused,
            reissue_trigger_lifetime_left_seconds,
        })
    }

    /// Credential configuration governed by this policy.
    #[must_use]
    pub const fn credential_configuration_id(&self) -> &NonEmptyIdentifier {
        &self.credential_configuration_id
    }

    /// Selected reuse method.
    #[must_use]
    pub const fn method(&self) -> CredentialReuseMethod {
        self.method
    }

    /// Required credential batch size, when applicable.
    #[must_use]
    pub const fn batch_size(&self) -> Option<u32> {
        self.batch_size
    }

    /// Remaining unused credentials that trigger reissuance.
    #[must_use]
    pub const fn reissue_trigger_unused(&self) -> Option<u32> {
        self.reissue_trigger_unused
    }

    /// Remaining lifetime in seconds that triggers reissuance.
    #[must_use]
    pub const fn reissue_trigger_lifetime_left_seconds(&self) -> Option<u64> {
        self.reissue_trigger_lifetime_left_seconds
    }
}

impl core::fmt::Debug for CredentialReusePolicySelection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialReusePolicySelection(<redacted>)")
    }
}
