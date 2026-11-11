// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invocation-neutral ownership contract for a synchronous provider transport.

use thiserror::Error;
use zeroize::Zeroizing;

/// Result returned by a provider byte transport.
pub type ProviderTransportResult<T> = Result<T, ProviderTransportError>;

/// Typed transport failure without provider exception text.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet provider transport failed: {reason}")]
pub struct ProviderTransportError {
    /// Stable transport reason for deterministic adapter mapping.
    pub reason: ProviderTransportErrorReason,
}

impl ProviderTransportError {
    /// Construct a transport error from a stable reason.
    #[must_use]
    pub const fn new(reason: ProviderTransportErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable failures outside a decoded provider response.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTransportErrorReason {
    /// Required platform callback or provider became unavailable.
    #[error("unavailable")]
    Unavailable,
    /// Callback rejected the invocation without a decoded provider response.
    #[error("rejected")]
    Rejected,
    /// Callback reported a response larger than the negotiated fixed limit.
    #[error("response_too_large")]
    ResponseTooLarge,
}

/// Synchronous byte transport used by native Rust and downstream SDK adapters.
///
/// Implementations invoke the provider exactly once. They must not probe and
/// retry a mutating request for output-size negotiation. Returned bytes own and
/// zeroize their allocation.
pub trait ProviderTransport {
    /// Invoke one encoded provider request under the validated response bound.
    fn invoke(
        &mut self,
        request: &[u8],
        max_response_bytes: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>>;
}
