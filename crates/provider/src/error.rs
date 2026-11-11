// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed, privacy-safe provider-contract errors.

use thiserror::Error;

/// Result type for provider contract validation.
pub type ProviderContractResult<T> = Result<T, ProviderContractError>;

/// Provider contract failure with a stable, allocation-free reason.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet provider contract failed: {reason}")]
pub struct ProviderContractError {
    /// Stable reason suitable for deterministic adapter status mapping.
    pub reason: ProviderContractErrorReason,
}

impl ProviderContractError {
    /// Construct an error from its stable reason.
    #[must_use]
    pub const fn new(reason: ProviderContractErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable provider validation failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderContractErrorReason {
    /// Descriptor or request used an unsupported contract version.
    #[error("unsupported_contract_version")]
    UnsupportedContractVersion,
    /// Descriptor invocation mode did not match the adapter.
    #[error("invocation_mode_mismatch")]
    InvocationModeMismatch,
    /// Descriptor omitted a required provider capability.
    #[error("capability_missing")]
    CapabilityMissing,
    /// Descriptor repeated a provider capability.
    #[error("capability_duplicate")]
    CapabilityDuplicate,
    /// Descriptor included an unspecified or unknown capability.
    #[error("capability_unknown")]
    CapabilityUnknown,
    /// Descriptor response bound did not match version-1 policy.
    #[error("response_limit_invalid")]
    ResponseLimitInvalid,
    /// Adapter supplied a zero executor identifier.
    #[error("executor_id_invalid")]
    ExecutorIdInvalid,
    /// Executor exhausted its request identifier space.
    #[error("request_id_exhausted")]
    RequestIdExhausted,
    /// Provider request omitted its operation variant.
    #[error("request_missing")]
    RequestMissing,
    /// Provider response used a different contract version.
    #[error("response_version_mismatch")]
    ResponseVersionMismatch,
    /// Provider response belonged to another executor.
    #[error("response_executor_mismatch")]
    ResponseExecutorMismatch,
    /// Provider response did not echo the request identifier.
    #[error("response_request_mismatch")]
    ResponseRequestMismatch,
    /// Provider response omitted success and error outcomes.
    #[error("response_outcome_missing")]
    ResponseOutcomeMissing,
    /// Provider success omitted its result variant.
    #[error("response_result_missing")]
    ResponseResultMissing,
    /// Provider success returned a result for another request method.
    #[error("response_result_mismatch")]
    ResponseResultMismatch,
    /// Provider returned an unspecified or unknown error reason.
    #[error("response_error_unknown")]
    ResponseErrorUnknown,
}
