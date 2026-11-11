// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed failures reported by host-injected provider capabilities.

use thiserror::Error;

/// Failure from a host-injected trusted clock or authority verifier.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet provider host capability failed: {reason}")]
pub struct ProviderHostCapabilityError {
    /// Stable reason for deterministic runtime mapping.
    pub reason: ProviderHostCapabilityErrorReason,
}

impl ProviderHostCapabilityError {
    /// Construct a host capability error from a stable reason.
    #[must_use]
    pub const fn new(reason: ProviderHostCapabilityErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable host capability failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHostCapabilityErrorReason {
    /// The capability could not produce a trustworthy answer.
    #[error("unavailable")]
    Unavailable,
    /// The capability evaluated the input and refused it.
    #[error("rejected")]
    Rejected,
}
