// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate correlation and exact request/result pairing for provider calls.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use crate::{
    ProviderContractError, ProviderContractErrorReason, ProviderContractResult,
    WALLET_PROVIDER_CONTRACT_VERSION,
};

/// One method in the fixed version-1 provider catalog.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderMethod {
    /// Reserve or replay a canonical operation.
    BeginOperation,
    /// Commit exact canonical response bytes.
    CommitOperation,
    /// Read time from the owning security clock.
    ReadTrustedTime,
    /// Authenticate lifecycle evidence for the exact transition.
    VerifyLifecycleAuthority,
    /// Create Wallet lifecycle state.
    CreateWalletLifecycle,
    /// Read Wallet lifecycle state.
    GetWalletLifecycle,
    /// Replace Wallet lifecycle state at a revision.
    CompareAndSwapWalletLifecycle,
    /// Append Wallet lifecycle evidence.
    AppendWalletLifecycleEvidence,
    /// Create a credential record.
    CreateCredential,
    /// Read a credential record.
    GetCredential,
    /// Replace a credential record at a revision.
    CompareAndSwapCredential,
    /// Delete or tombstone a credential revision.
    DeleteCredential,
    /// Atomically claim a once-only presentation copy.
    ClaimPresentationCopy,
    /// Create or replace a Wallet-owned DID projection.
    SaveDidStorageRecord,
    /// Read a Wallet-owned DID projection.
    GetDidStorageRecord,
    /// Delete a Wallet-owned DID projection at an exact revision.
    DeleteDidStorageRecord,
    /// Create or replace a portable wrapped-key record.
    SavePortableKeyStorageRecord,
    /// Read a portable wrapped-key record.
    GetPortableKeyStorageRecord,
    /// Delete a portable wrapped-key record at an exact revision.
    DeletePortableKeyStorageRecord,
    /// Create or replace an installation-local hardware-key binding.
    SaveHardwareKeyBindingRecord,
    /// Read an installation-local hardware-key binding.
    GetHardwareKeyBindingRecord,
    /// Delete a hardware-key binding at an exact revision.
    DeleteHardwareKeyBindingRecord,
    /// Create or replace a flow snapshot.
    SaveFlowSnapshot,
    /// Read a flow snapshot.
    GetFlowSnapshot,
    /// Append a transaction log entry.
    AppendTransactionLog,
    /// Append a QTSP decision.
    AppendQtspDecision,
}

impl ProviderMethod {
    pub(crate) fn from_request(
        request: &pb::WalletProviderRequest,
    ) -> ProviderContractResult<Self> {
        use pb::wallet_provider_request::Request;
        match request.request.as_ref() {
            Some(Request::BeginOperation(_)) => Ok(Self::BeginOperation),
            Some(Request::CommitOperation(_)) => Ok(Self::CommitOperation),
            Some(Request::ReadTrustedTime(_)) => Ok(Self::ReadTrustedTime),
            Some(Request::VerifyLifecycleAuthority(_)) => Ok(Self::VerifyLifecycleAuthority),
            Some(Request::CreateWalletLifecycle(_)) => Ok(Self::CreateWalletLifecycle),
            Some(Request::GetWalletLifecycle(_)) => Ok(Self::GetWalletLifecycle),
            Some(Request::CompareAndSwapWalletLifecycle(_)) => {
                Ok(Self::CompareAndSwapWalletLifecycle)
            }
            Some(Request::AppendWalletLifecycleEvidence(_)) => {
                Ok(Self::AppendWalletLifecycleEvidence)
            }
            Some(Request::CreateCredential(_)) => Ok(Self::CreateCredential),
            Some(Request::GetCredential(_)) => Ok(Self::GetCredential),
            Some(Request::CompareAndSwapCredential(_)) => Ok(Self::CompareAndSwapCredential),
            Some(Request::DeleteCredential(_)) => Ok(Self::DeleteCredential),
            Some(Request::ClaimPresentationCopy(_)) => Ok(Self::ClaimPresentationCopy),
            Some(Request::SaveDidStorageRecord(_)) => Ok(Self::SaveDidStorageRecord),
            Some(Request::GetDidStorageRecord(_)) => Ok(Self::GetDidStorageRecord),
            Some(Request::DeleteDidStorageRecord(_)) => Ok(Self::DeleteDidStorageRecord),
            Some(Request::SavePortableKeyStorageRecord(_)) => {
                Ok(Self::SavePortableKeyStorageRecord)
            }
            Some(Request::GetPortableKeyStorageRecord(_)) => Ok(Self::GetPortableKeyStorageRecord),
            Some(Request::DeletePortableKeyStorageRecord(_)) => {
                Ok(Self::DeletePortableKeyStorageRecord)
            }
            Some(Request::SaveHardwareKeyBindingRecord(_)) => {
                Ok(Self::SaveHardwareKeyBindingRecord)
            }
            Some(Request::GetHardwareKeyBindingRecord(_)) => Ok(Self::GetHardwareKeyBindingRecord),
            Some(Request::DeleteHardwareKeyBindingRecord(_)) => {
                Ok(Self::DeleteHardwareKeyBindingRecord)
            }
            Some(Request::SaveFlowSnapshot(_)) => Ok(Self::SaveFlowSnapshot),
            Some(Request::GetFlowSnapshot(_)) => Ok(Self::GetFlowSnapshot),
            Some(Request::AppendTransactionLog(_)) => Ok(Self::AppendTransactionLog),
            Some(Request::AppendQtspDecision(_)) => Ok(Self::AppendQtspDecision),
            None => Err(ProviderContractError::new(
                ProviderContractErrorReason::RequestMissing,
            )),
        }
    }

    fn matches_result(self, result: &pb::wallet_provider_result::Result) -> bool {
        use pb::wallet_provider_result::Result;
        matches!(
            (self, result),
            (Self::BeginOperation, Result::BeginOperation(_))
                | (Self::CommitOperation, Result::CommitOperation(_))
                | (Self::ReadTrustedTime, Result::ReadTrustedTime(_))
                | (
                    Self::VerifyLifecycleAuthority,
                    Result::VerifyLifecycleAuthority(_)
                )
                | (
                    Self::CreateWalletLifecycle,
                    Result::CreateWalletLifecycle(_)
                )
                | (Self::GetWalletLifecycle, Result::GetWalletLifecycle(_))
                | (
                    Self::CompareAndSwapWalletLifecycle,
                    Result::CompareAndSwapWalletLifecycle(_)
                )
                | (
                    Self::AppendWalletLifecycleEvidence,
                    Result::AppendWalletLifecycleEvidence(_)
                )
                | (Self::CreateCredential, Result::CreateCredential(_))
                | (Self::GetCredential, Result::GetCredential(_))
                | (
                    Self::CompareAndSwapCredential,
                    Result::CompareAndSwapCredential(_)
                )
                | (Self::DeleteCredential, Result::DeleteCredential(_))
                | (
                    Self::ClaimPresentationCopy,
                    Result::ClaimPresentationCopy(_)
                )
                | (Self::SaveDidStorageRecord, Result::SaveDidStorageRecord(_))
                | (Self::GetDidStorageRecord, Result::GetDidStorageRecord(_))
                | (
                    Self::DeleteDidStorageRecord,
                    Result::DeleteDidStorageRecord(_)
                )
                | (
                    Self::SavePortableKeyStorageRecord,
                    Result::SavePortableKeyStorageRecord(_)
                )
                | (
                    Self::GetPortableKeyStorageRecord,
                    Result::GetPortableKeyStorageRecord(_)
                )
                | (
                    Self::DeletePortableKeyStorageRecord,
                    Result::DeletePortableKeyStorageRecord(_)
                )
                | (
                    Self::SaveHardwareKeyBindingRecord,
                    Result::SaveHardwareKeyBindingRecord(_)
                )
                | (
                    Self::GetHardwareKeyBindingRecord,
                    Result::GetHardwareKeyBindingRecord(_)
                )
                | (
                    Self::DeleteHardwareKeyBindingRecord,
                    Result::DeleteHardwareKeyBindingRecord(_)
                )
                | (Self::SaveFlowSnapshot, Result::SaveFlowSnapshot(_))
                | (Self::GetFlowSnapshot, Result::GetFlowSnapshot(_))
                | (Self::AppendTransactionLog, Result::AppendTransactionLog(_))
                | (Self::AppendQtspDecision, Result::AppendQtspDecision(_))
        )
    }
}

/// Validated semantic outcome of one provider exchange.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ValidatedProviderOutcome {
    /// The response contains the correctly paired success result.
    Success,
    /// The response contains a known, non-unspecified provider error.
    Error(pb::WalletProviderErrorReason),
}

/// Validate response version, executor, request correlation, and result pairing.
pub fn validate_provider_exchange(
    request: &pb::WalletProviderRequest,
    response: &pb::WalletProviderResponse,
) -> ProviderContractResult<ValidatedProviderOutcome> {
    let method = ProviderMethod::from_request(request)?;
    if request.contract_version != WALLET_PROVIDER_CONTRACT_VERSION
        || response.contract_version != WALLET_PROVIDER_CONTRACT_VERSION
    {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::ResponseVersionMismatch,
        ));
    }
    if request.executor_id == 0 || response.executor_id != request.executor_id {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::ResponseExecutorMismatch,
        ));
    }
    if request.request_id == 0 || response.request_id != request.request_id {
        return Err(ProviderContractError::new(
            ProviderContractErrorReason::ResponseRequestMismatch,
        ));
    }

    match response.outcome.as_ref() {
        Some(pb::wallet_provider_response::Outcome::Result(result)) => {
            let paired = result.result.as_ref().ok_or(ProviderContractError::new(
                ProviderContractErrorReason::ResponseResultMissing,
            ))?;
            if !method.matches_result(paired) {
                return Err(ProviderContractError::new(
                    ProviderContractErrorReason::ResponseResultMismatch,
                ));
            }
            Ok(ValidatedProviderOutcome::Success)
        }
        Some(pb::wallet_provider_response::Outcome::Error(error)) => {
            let reason = error.reason.as_known().ok_or(ProviderContractError::new(
                ProviderContractErrorReason::ResponseErrorUnknown,
            ))?;
            if reason == pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_UNSPECIFIED {
                return Err(ProviderContractError::new(
                    ProviderContractErrorReason::ResponseErrorUnknown,
                ));
            }
            Ok(ValidatedProviderOutcome::Error(reason))
        }
        None => Err(ProviderContractError::new(
            ProviderContractErrorReason::ResponseOutcomeMissing,
        )),
    }
}
