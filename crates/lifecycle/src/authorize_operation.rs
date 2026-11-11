// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operation authorization against the durable Wallet Unit lifecycle state.

use crate::{
    LifecycleError, LifecycleErrorReason, LifecycleResult, WalletLifecycleRecord,
    WalletLifecycleState, WalletOperation,
};

/// Enforce whether a regulated wallet operation is allowed in the current state.
pub fn ensure_wallet_operation_allowed(
    record: &WalletLifecycleRecord,
    operation: WalletOperation,
) -> LifecycleResult<()> {
    match record.state {
        WalletLifecycleState::Active => Ok(()),
        WalletLifecycleState::Suspended => allow_suspended_operation(operation),
        WalletLifecycleState::Withdrawn => allow_withdrawn_operation(operation),
        WalletLifecycleState::Deleted => allow_deleted_operation(operation),
        WalletLifecycleState::Unprovisioned
        | WalletLifecycleState::Provisioning
        | WalletLifecycleState::RecoveryPending
        | WalletLifecycleState::MigrationPending
        | WalletLifecycleState::WithdrawalPending
        | WalletLifecycleState::DeletionPending
        | WalletLifecycleState::Failed => allow_pending_operation(record, operation),
    }
}

fn allow_suspended_operation(operation: WalletOperation) -> LifecycleResult<()> {
    match operation {
        WalletOperation::RefreshCredentialStatus
        | WalletOperation::ReadTransactionHistory
        | WalletOperation::RecordTransactionHistory
        | WalletOperation::ReadWalletRecords
        | WalletOperation::DeleteWallet => Ok(()),
        // A suspended Wallet Unit must not obtain a fresh attestation that
        // would outlive the suspension; renewal resumes after reactivation.
        WalletOperation::BeginIssuance
        | WalletOperation::PresentCredential
        | WalletOperation::SignWithWalletKey
        | WalletOperation::RenewAttestation => {
            Err(LifecycleError::new(LifecycleErrorReason::WalletNotActive))
        }
    }
}

fn allow_pending_operation(
    record: &WalletLifecycleRecord,
    operation: WalletOperation,
) -> LifecycleResult<()> {
    match operation {
        WalletOperation::ReadTransactionHistory
        | WalletOperation::RecordTransactionHistory
        | WalletOperation::DeleteWallet => Ok(()),
        // Once withdrawal or deletion has begun, credential payloads and flow
        // state stay closed even though the unit is not yet terminal.
        WalletOperation::ReadWalletRecords if !retiring(record) => Ok(()),
        WalletOperation::ReadWalletRecords
        | WalletOperation::BeginIssuance
        | WalletOperation::PresentCredential
        | WalletOperation::SignWithWalletKey
        | WalletOperation::RefreshCredentialStatus
        | WalletOperation::RenewAttestation => {
            Err(LifecycleError::new(LifecycleErrorReason::WalletNotActive))
        }
    }
}

/// Return whether a pending or failed unit is withdrawing or deleting.
///
/// Only pending and failed states reach this check; `Withdrawn` has its own
/// rule.
fn retiring(record: &WalletLifecycleRecord) -> bool {
    let retiring_state = |state: WalletLifecycleState| {
        matches!(
            state,
            WalletLifecycleState::WithdrawalPending | WalletLifecycleState::DeletionPending
        )
    };
    retiring_state(record.state)
        || (record.state == WalletLifecycleState::Failed
            && record.failed_from.is_some_and(retiring_state))
}

fn allow_withdrawn_operation(operation: WalletOperation) -> LifecycleResult<()> {
    match operation {
        WalletOperation::ReadTransactionHistory | WalletOperation::DeleteWallet => Ok(()),
        WalletOperation::BeginIssuance
        | WalletOperation::PresentCredential
        | WalletOperation::SignWithWalletKey
        | WalletOperation::RefreshCredentialStatus
        | WalletOperation::RecordTransactionHistory
        | WalletOperation::ReadWalletRecords
        | WalletOperation::RenewAttestation => {
            Err(LifecycleError::new(LifecycleErrorReason::WalletWithdrawn))
        }
    }
}

fn allow_deleted_operation(operation: WalletOperation) -> LifecycleResult<()> {
    match operation {
        // Erasing records left behind after deletion completed, for example
        // after a crash or in a separate store, must stay possible.
        WalletOperation::ReadTransactionHistory | WalletOperation::DeleteWallet => Ok(()),
        WalletOperation::BeginIssuance
        | WalletOperation::PresentCredential
        | WalletOperation::SignWithWalletKey
        | WalletOperation::RefreshCredentialStatus
        | WalletOperation::RecordTransactionHistory
        | WalletOperation::ReadWalletRecords
        | WalletOperation::RenewAttestation => {
            Err(LifecycleError::new(LifecycleErrorReason::WalletDeleted))
        }
    }
}
