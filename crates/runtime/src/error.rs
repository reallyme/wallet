// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed runtime errors for generated wallet service handlers.

use buffa::{Enumeration, MessageField};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::ConvertError;
use thiserror::Error;

/// Result type for wallet runtime handlers.
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Runtime error with a stable, non-sensitive reason code.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet runtime operation failed: {reason}")]
pub struct RuntimeError {
    /// Stable reason code.
    pub reason: RuntimeErrorReason,
}

impl RuntimeError {
    /// Construct a runtime error from a stable reason.
    #[must_use]
    pub const fn new(reason: RuntimeErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable wallet runtime failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeErrorReason {
    /// Request DTO was missing required fields or failed validation.
    #[error("invalid_request")]
    InvalidRequest,
    /// Injected trusted clock failed or returned an unsupported time.
    #[error("trusted_clock_unavailable")]
    TrustedClockUnavailable,
    /// Lifecycle evidence is dated after or too far before trusted time.
    #[error("lifecycle_clock_skew")]
    LifecycleClockSkew,
    /// Injected credential storage backend rejected the operation.
    #[error("credential_store_rejected")]
    CredentialStoreRejected,
    /// Injected flow snapshot store rejected the operation.
    #[error("flow_snapshot_store_rejected")]
    FlowSnapshotStoreRejected,
    /// Injected lifecycle store rejected the operation.
    #[error("lifecycle_store_rejected")]
    LifecycleStoreRejected,
    /// Durable lifecycle state forbids this regulated action.
    #[error("lifecycle_policy_denied")]
    LifecyclePolicyDenied,
    /// Injected lifecycle evidence store rejected the operation.
    #[error("lifecycle_evidence_store_rejected")]
    LifecycleEvidenceStoreRejected,
    /// Injected presentation-copy backend rejected the operation.
    #[error("presentation_copy_store_rejected")]
    PresentationCopyStoreRejected,
    /// Injected log backend rejected the operation.
    #[error("log_store_rejected")]
    LogStoreRejected,
    /// Injected DID/key storage backend rejected the operation.
    #[error("key_storage_rejected")]
    KeyStorageRejected,
    /// Credential state changed after the runtime read its revision.
    #[error("credential_revision_conflict")]
    CredentialRevisionConflict,
    /// Wallet lifecycle state changed after the runtime read its revision.
    #[error("lifecycle_revision_conflict")]
    LifecycleRevisionConflict,
    /// Canonical mutation omitted its required idempotency key.
    #[error("idempotency_key_missing")]
    IdempotencyKeyMissing,
    /// Canonical operation supplied a malformed or all-zero idempotency key.
    #[error("idempotency_key_invalid")]
    IdempotencyKeyInvalid,
    /// An idempotency key was reused for a different canonical request.
    #[error("idempotency_conflict")]
    IdempotencyConflict,
    /// The same canonical mutation is reserved but not yet committed.
    #[error("operation_in_progress")]
    OperationInProgress,
    /// The injected operation journal rejected reservation or response commit.
    #[error("idempotency_store_rejected")]
    IdempotencyStoreRejected,
    /// A flow snapshot create or replacement used a stale revision.
    #[error("flow_snapshot_revision_conflict")]
    FlowSnapshotRevisionConflict,
    /// A credential create targeted an identifier that already exists.
    #[error("credential_already_exists")]
    CredentialAlreadyExists,
    /// A lifecycle create targeted a Wallet instance that already exists.
    #[error("lifecycle_already_exists")]
    LifecycleAlreadyExists,
    /// A DID/key record changed after the caller observed its revision.
    #[error("key_storage_revision_conflict")]
    KeyStorageRevisionConflict,
    /// A once-only presentation copy was already delivered for this request.
    #[error("presentation_copy_already_claimed")]
    PresentationCopyAlreadyClaimed,
    /// The mutation succeeded but its result exceeded the public wire limit.
    #[error("operation_response_too_large")]
    OperationResponseTooLarge,
    /// A requested durable record does not exist.
    #[error("record_not_found")]
    RecordNotFound,
    /// The v1 wire operation is never executed by this runtime.
    #[error("operation_unsupported")]
    OperationUnsupported,
    /// The parent credential is missing or inactive; no copy was claimed.
    #[error("credential_not_active")]
    CredentialNotActive,
    /// A copy was burned but withheld because its credential became inactive
    /// during the claim.
    #[error("claimed_copy_discarded")]
    ClaimedCopyDiscarded,
    /// The provider does not implement a capability this operation needs.
    #[error("provider_capability_unsupported")]
    ProviderCapabilityUnsupported,
    /// An audit record is dated beyond the accepted skew from trusted time.
    #[error("record_clock_skew")]
    RecordClockSkew,
}

impl From<ConvertError> for RuntimeError {
    fn from(_error: ConvertError) -> Self {
        Self::new(RuntimeErrorReason::InvalidRequest)
    }
}

/// Map runtime reasons to the stable public Wallet reason taxonomy.
#[must_use]
pub const fn map_runtime_error_reason(reason: RuntimeErrorReason) -> pb::WalletErrorReason {
    match reason {
        RuntimeErrorReason::InvalidRequest | RuntimeErrorReason::OperationUnsupported => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID
        }
        RuntimeErrorReason::LifecycleClockSkew | RuntimeErrorReason::RecordClockSkew => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID
        }
        RuntimeErrorReason::ProviderCapabilityUnsupported => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_BACKEND_UNAVAILABLE
        }
        RuntimeErrorReason::TrustedClockUnavailable => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE
        }
        RuntimeErrorReason::LifecyclePolicyDenied => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        RuntimeErrorReason::CredentialStoreRejected
        | RuntimeErrorReason::FlowSnapshotStoreRejected
        | RuntimeErrorReason::LifecycleStoreRejected
        | RuntimeErrorReason::LifecycleEvidenceStoreRejected
        | RuntimeErrorReason::PresentationCopyStoreRejected
        | RuntimeErrorReason::KeyStorageRejected => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_STORAGE_UNAVAILABLE
        }
        RuntimeErrorReason::LogStoreRejected => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_LOG_APPEND_REJECTED
        }
        RuntimeErrorReason::CredentialRevisionConflict
        | RuntimeErrorReason::LifecycleRevisionConflict
        | RuntimeErrorReason::FlowSnapshotRevisionConflict
        | RuntimeErrorReason::KeyStorageRevisionConflict => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_REVISION_CONFLICT
        }
        RuntimeErrorReason::IdempotencyKeyMissing | RuntimeErrorReason::IdempotencyKeyInvalid => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_KEY_INVALID
        }
        RuntimeErrorReason::IdempotencyConflict => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_CONFLICT
        }
        RuntimeErrorReason::OperationInProgress => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_OPERATION_IN_PROGRESS
        }
        RuntimeErrorReason::IdempotencyStoreRejected => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_IDEMPOTENCY_STORE_UNAVAILABLE
        }
        RuntimeErrorReason::CredentialAlreadyExists
        | RuntimeErrorReason::LifecycleAlreadyExists
        | RuntimeErrorReason::PresentationCopyAlreadyClaimed
        | RuntimeErrorReason::CredentialNotActive
        | RuntimeErrorReason::ClaimedCopyDiscarded => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_STATE
        }
        RuntimeErrorReason::OperationResponseTooLarge => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_SERIALIZATION_FAILED
        }
        RuntimeErrorReason::RecordNotFound => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_RECORD_NOT_FOUND
        }
    }
}

/// Map runtime reasons to their exact public detail discriminants.
#[must_use]
pub const fn map_runtime_detail_reason(reason: RuntimeErrorReason) -> pb::RuntimeErrorReason {
    match reason {
        RuntimeErrorReason::InvalidRequest => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_INVALID_REQUEST
        }
        RuntimeErrorReason::OperationUnsupported => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED
        }
        RuntimeErrorReason::CredentialNotActive => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_NOT_ACTIVE
        }
        RuntimeErrorReason::ClaimedCopyDiscarded => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CLAIMED_COPY_DISCARDED
        }
        RuntimeErrorReason::ProviderCapabilityUnsupported => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_PROVIDER_CAPABILITY_UNSUPPORTED
        }
        RuntimeErrorReason::RecordClockSkew => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_RECORD_CLOCK_SKEW
        }
        RuntimeErrorReason::TrustedClockUnavailable => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_TRUSTED_CLOCK_UNAVAILABLE
        }
        RuntimeErrorReason::LifecycleClockSkew => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_CLOCK_SKEW
        }
        RuntimeErrorReason::CredentialStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_STORE_REJECTED
        }
        RuntimeErrorReason::FlowSnapshotStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_FLOW_SNAPSHOT_STORE_REJECTED
        }
        RuntimeErrorReason::LifecycleStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_STORE_REJECTED
        }
        RuntimeErrorReason::LifecyclePolicyDenied => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_POLICY_DENIED
        }
        RuntimeErrorReason::LifecycleEvidenceStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_EVIDENCE_STORE_REJECTED
        }
        RuntimeErrorReason::PresentationCopyStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_PRESENTATION_COPY_STORE_REJECTED
        }
        RuntimeErrorReason::LogStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LOG_STORE_REJECTED
        }
        RuntimeErrorReason::KeyStorageRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_KEY_STORAGE_REJECTED
        }
        RuntimeErrorReason::CredentialRevisionConflict => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_REVISION_CONFLICT
        }
        RuntimeErrorReason::LifecycleRevisionConflict => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_REVISION_CONFLICT
        }
        RuntimeErrorReason::IdempotencyKeyMissing => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_KEY_MISSING
        }
        RuntimeErrorReason::IdempotencyKeyInvalid => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_KEY_INVALID
        }
        RuntimeErrorReason::IdempotencyConflict => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_CONFLICT
        }
        RuntimeErrorReason::OperationInProgress => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_IN_PROGRESS
        }
        RuntimeErrorReason::IdempotencyStoreRejected => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_IDEMPOTENCY_STORE_REJECTED
        }
        RuntimeErrorReason::FlowSnapshotRevisionConflict => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_FLOW_SNAPSHOT_REVISION_CONFLICT
        }
        RuntimeErrorReason::CredentialAlreadyExists => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_CREDENTIAL_ALREADY_EXISTS
        }
        RuntimeErrorReason::LifecycleAlreadyExists => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_LIFECYCLE_ALREADY_EXISTS
        }
        RuntimeErrorReason::KeyStorageRevisionConflict => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_KEY_STORAGE_REVISION_CONFLICT
        }
        RuntimeErrorReason::PresentationCopyAlreadyClaimed => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_PRESENTATION_COPY_ALREADY_CLAIMED
        }
        RuntimeErrorReason::OperationResponseTooLarge => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_RESPONSE_TOO_LARGE
        }
        RuntimeErrorReason::RecordNotFound => {
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_RECORD_NOT_FOUND
        }
    }
}

/// Build the privacy-safe generated error detail for a runtime failure.
#[must_use]
pub fn runtime_error_to_proto(reason: RuntimeErrorReason) -> pb::WalletError {
    pb::WalletError {
        reason: map_runtime_error_reason(reason).into(),
        detail: Some(pb::wallet_error::Detail::Runtime(
            map_runtime_detail_reason(reason).into(),
        )),
        ..Default::default()
    }
}

/// Build the canonical cross-layer envelope for an expected runtime failure.
#[must_use]
pub fn runtime_error_envelope(reason: RuntimeErrorReason) -> pb::WalletErrorEnvelope {
    wallet_error_envelope(runtime_error_to_proto(reason))
}

/// Wrap a known Wallet error in the canonical cross-layer envelope.
///
/// Runtime adapters use this helper so every transport emits the same stable
/// Wallet and identity-stack reason pair without duplicating mapping policy.
#[must_use]
pub fn wallet_error_envelope(wallet_error: pb::WalletError) -> pb::WalletErrorEnvelope {
    // Unknown wire values, including negative values whose magnitude happens
    // to name a known reason, must never be promoted into a known stack code.
    let reason_code = match wallet_error.reason.as_known() {
        Some(known) => u32::try_from(known.to_i32()).unwrap_or_default(),
        None => 0,
    };
    let stack_error = IdentityStackError {
        domain: IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_WALLET.into(),
        reason_code,
        ..Default::default()
    };
    pb::WalletErrorEnvelope {
        stack: MessageField::some(stack_error),
        wallet: MessageField::some(wallet_error),
        ..Default::default()
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
