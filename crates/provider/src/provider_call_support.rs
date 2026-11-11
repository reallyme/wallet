// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared construction and privacy-safe failure mapping for provider calls.

use buffa::MessageField;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_runtime::{RecordRevision, RuntimeError, RuntimeErrorReason, RuntimeResult};

use crate::ProviderMethod;

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn provider_request(
    request: pb::wallet_provider_request::Request,
) -> pb::WalletProviderRequest {
    // Hardened generated owners implement Drop and cannot use struct-update
    // syntax without moving their hidden unknown-field owner.
    let mut envelope = pb::WalletProviderRequest::default();
    envelope.request = Some(request);
    envelope
}

pub(crate) fn revision_to_proto(revision: RecordRevision) -> pb::RecordRevision {
    pb::RecordRevision {
        value: revision.value(),
        ..Default::default()
    }
}

pub(crate) fn require_revision<P>(
    revision: &MessageField<pb::RecordRevision, P>,
    method: ProviderMethod,
) -> RuntimeResult<RecordRevision>
where
    P: buffa::ProtoBox<pb::RecordRevision>,
{
    match revision.as_option() {
        Some(value) if value.value != 0 => Ok(RecordRevision::new(value.value)),
        Some(_) | None => Err(runtime_rejected(method)),
    }
}

pub(crate) fn runtime_rejected(method: ProviderMethod) -> RuntimeError {
    RuntimeError::new(match method {
        ProviderMethod::ReadTrustedTime => RuntimeErrorReason::TrustedClockUnavailable,
        ProviderMethod::VerifyLifecycleAuthority => RuntimeErrorReason::LifecyclePolicyDenied,
        ProviderMethod::BeginOperation | ProviderMethod::CommitOperation => {
            RuntimeErrorReason::IdempotencyStoreRejected
        }
        ProviderMethod::CreateWalletLifecycle
        | ProviderMethod::GetWalletLifecycle
        | ProviderMethod::CompareAndSwapWalletLifecycle => {
            RuntimeErrorReason::LifecycleStoreRejected
        }
        ProviderMethod::AppendWalletLifecycleEvidence => {
            RuntimeErrorReason::LifecycleEvidenceStoreRejected
        }
        ProviderMethod::CreateCredential
        | ProviderMethod::GetCredential
        | ProviderMethod::CompareAndSwapCredential
        | ProviderMethod::DeleteCredential => RuntimeErrorReason::CredentialStoreRejected,
        ProviderMethod::ClaimPresentationCopy => RuntimeErrorReason::PresentationCopyStoreRejected,
        ProviderMethod::SaveDidStorageRecord
        | ProviderMethod::GetDidStorageRecord
        | ProviderMethod::DeleteDidStorageRecord
        | ProviderMethod::SavePortableKeyStorageRecord
        | ProviderMethod::GetPortableKeyStorageRecord
        | ProviderMethod::DeletePortableKeyStorageRecord
        | ProviderMethod::SaveHardwareKeyBindingRecord
        | ProviderMethod::GetHardwareKeyBindingRecord
        | ProviderMethod::DeleteHardwareKeyBindingRecord => RuntimeErrorReason::KeyStorageRejected,
        ProviderMethod::SaveFlowSnapshot | ProviderMethod::GetFlowSnapshot => {
            RuntimeErrorReason::FlowSnapshotStoreRejected
        }
        ProviderMethod::AppendTransactionLog | ProviderMethod::AppendQtspDecision => {
            RuntimeErrorReason::LogStoreRejected
        }
    })
}

pub(crate) fn map_provider_error(
    method: ProviderMethod,
    reason: pb::WalletProviderErrorReason,
) -> RuntimeError {
    use pb::WalletProviderErrorReason as Reason;
    let runtime_reason = match (method, reason) {
        (
            ProviderMethod::GetCredential
            | ProviderMethod::GetWalletLifecycle
            | ProviderMethod::GetFlowSnapshot
            | ProviderMethod::GetDidStorageRecord
            | ProviderMethod::GetPortableKeyStorageRecord
            | ProviderMethod::GetHardwareKeyBindingRecord,
            Reason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND,
        ) => RuntimeErrorReason::RecordNotFound,
        (ProviderMethod::CreateCredential, Reason::WALLET_PROVIDER_ERROR_REASON_ALREADY_EXISTS) => {
            RuntimeErrorReason::CredentialAlreadyExists
        }
        (
            ProviderMethod::CreateWalletLifecycle,
            Reason::WALLET_PROVIDER_ERROR_REASON_ALREADY_EXISTS,
        ) => RuntimeErrorReason::LifecycleAlreadyExists,
        (
            ProviderMethod::CompareAndSwapCredential | ProviderMethod::DeleteCredential,
            Reason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT,
        ) => RuntimeErrorReason::CredentialRevisionConflict,
        (
            ProviderMethod::CompareAndSwapWalletLifecycle,
            Reason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT,
        ) => RuntimeErrorReason::LifecycleRevisionConflict,
        (
            ProviderMethod::SaveFlowSnapshot,
            Reason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT,
        ) => RuntimeErrorReason::FlowSnapshotRevisionConflict,
        (
            ProviderMethod::SaveDidStorageRecord
            | ProviderMethod::DeleteDidStorageRecord
            | ProviderMethod::SavePortableKeyStorageRecord
            | ProviderMethod::DeletePortableKeyStorageRecord
            | ProviderMethod::SaveHardwareKeyBindingRecord
            | ProviderMethod::DeleteHardwareKeyBindingRecord,
            Reason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT,
        ) => RuntimeErrorReason::KeyStorageRevisionConflict,
        // Journal outcomes are meaningful only for the journal methods; the
        // same reason from a data method is a provider fault.
        (
            ProviderMethod::BeginOperation | ProviderMethod::CommitOperation,
            Reason::WALLET_PROVIDER_ERROR_REASON_IDEMPOTENCY_CONFLICT,
        ) => RuntimeErrorReason::IdempotencyConflict,
        (
            ProviderMethod::BeginOperation | ProviderMethod::CommitOperation,
            Reason::WALLET_PROVIDER_ERROR_REASON_OPERATION_IN_PROGRESS,
        ) => RuntimeErrorReason::OperationInProgress,
        // A missing provider capability fails closed with a typed reason.
        (_, Reason::WALLET_PROVIDER_ERROR_REASON_UNSUPPORTED_CAPABILITY) => {
            RuntimeErrorReason::ProviderCapabilityUnsupported
        }
        (_, _) => return runtime_rejected(method),
    };
    RuntimeError::new(runtime_reason)
}

#[cfg(test)]
#[path = "provider_call_support_tests.rs"]
mod tests;
