// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use super::{ConvertError, ConvertErrorReason, ConvertResult};

/// Convert a wallet lifecycle state into protobuf.
#[must_use]
pub const fn wallet_lifecycle_state_to_proto(
    state: lifecycle::WalletLifecycleState,
) -> pb::WalletLifecycleState {
    match state {
        lifecycle::WalletLifecycleState::Unprovisioned => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_UNPROVISIONED
        }
        lifecycle::WalletLifecycleState::Provisioning => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_PROVISIONING
        }
        lifecycle::WalletLifecycleState::Active => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_ACTIVE
        }
        lifecycle::WalletLifecycleState::Suspended => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_SUSPENDED
        }
        lifecycle::WalletLifecycleState::RecoveryPending => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_RECOVERY_PENDING
        }
        lifecycle::WalletLifecycleState::MigrationPending => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_MIGRATION_PENDING
        }
        lifecycle::WalletLifecycleState::WithdrawalPending => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_WITHDRAWAL_PENDING
        }
        lifecycle::WalletLifecycleState::DeletionPending => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_DELETION_PENDING
        }
        lifecycle::WalletLifecycleState::Withdrawn => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_WITHDRAWN
        }
        lifecycle::WalletLifecycleState::Deleted => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_DELETED
        }
        lifecycle::WalletLifecycleState::Failed => {
            pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_FAILED
        }
    }
}

/// Convert a generated protobuf lifecycle state into wallet-core state.
pub const fn wallet_lifecycle_state_from_proto(
    state: pb::WalletLifecycleState,
) -> ConvertResult<lifecycle::WalletLifecycleState> {
    match state {
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_UNPROVISIONED => {
            Ok(lifecycle::WalletLifecycleState::Unprovisioned)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_PROVISIONING => {
            Ok(lifecycle::WalletLifecycleState::Provisioning)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_ACTIVE => {
            Ok(lifecycle::WalletLifecycleState::Active)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_SUSPENDED => {
            Ok(lifecycle::WalletLifecycleState::Suspended)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_RECOVERY_PENDING => {
            Ok(lifecycle::WalletLifecycleState::RecoveryPending)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_MIGRATION_PENDING => {
            Ok(lifecycle::WalletLifecycleState::MigrationPending)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_WITHDRAWAL_PENDING => {
            Ok(lifecycle::WalletLifecycleState::WithdrawalPending)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_DELETION_PENDING => {
            Ok(lifecycle::WalletLifecycleState::DeletionPending)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_WITHDRAWN => {
            Ok(lifecycle::WalletLifecycleState::Withdrawn)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_DELETED => {
            Ok(lifecycle::WalletLifecycleState::Deleted)
        }
        pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_FAILED => {
            Ok(lifecycle::WalletLifecycleState::Failed)
        }
    }
}

/// Convert a wallet lifecycle event into protobuf.
#[must_use]
pub const fn wallet_lifecycle_event_to_proto(
    event: lifecycle::WalletLifecycleEvent,
) -> pb::WalletLifecycleEvent {
    match event {
        lifecycle::WalletLifecycleEvent::BeginProvisioning => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_PROVISIONING
        }
        lifecycle::WalletLifecycleEvent::CompleteProvisioning => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING
        }
        lifecycle::WalletLifecycleEvent::Suspend => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_SUSPEND
        }
        lifecycle::WalletLifecycleEvent::Reactivate => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_REACTIVATE
        }
        lifecycle::WalletLifecycleEvent::BeginRecovery => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_RECOVERY
        }
        lifecycle::WalletLifecycleEvent::CompleteRecovery => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_RECOVERY
        }
        lifecycle::WalletLifecycleEvent::BeginMigration => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_MIGRATION
        }
        lifecycle::WalletLifecycleEvent::CompleteMigration => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_MIGRATION
        }
        lifecycle::WalletLifecycleEvent::BeginWithdrawal => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_WITHDRAWAL
        }
        lifecycle::WalletLifecycleEvent::CompleteWithdrawal => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_WITHDRAWAL
        }
        lifecycle::WalletLifecycleEvent::BeginDeletion => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_DELETION
        }
        lifecycle::WalletLifecycleEvent::CompleteDeletion => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_DELETION
        }
        lifecycle::WalletLifecycleEvent::MarkFailed => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_MARK_FAILED
        }
        lifecycle::WalletLifecycleEvent::RetryProvisioning => {
            pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_RETRY_PROVISIONING
        }
    }
}

/// Convert a generated protobuf lifecycle event into wallet-core event.
pub const fn wallet_lifecycle_event_from_proto(
    event: pb::WalletLifecycleEvent,
) -> ConvertResult<lifecycle::WalletLifecycleEvent> {
    match event {
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_PROVISIONING => {
            Ok(lifecycle::WalletLifecycleEvent::BeginProvisioning)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_PROVISIONING => {
            Ok(lifecycle::WalletLifecycleEvent::CompleteProvisioning)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_SUSPEND => {
            Ok(lifecycle::WalletLifecycleEvent::Suspend)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_REACTIVATE => {
            Ok(lifecycle::WalletLifecycleEvent::Reactivate)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_RECOVERY => {
            Ok(lifecycle::WalletLifecycleEvent::BeginRecovery)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_RECOVERY => {
            Ok(lifecycle::WalletLifecycleEvent::CompleteRecovery)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_MIGRATION => {
            Ok(lifecycle::WalletLifecycleEvent::BeginMigration)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_MIGRATION => {
            Ok(lifecycle::WalletLifecycleEvent::CompleteMigration)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_WITHDRAWAL => {
            Ok(lifecycle::WalletLifecycleEvent::BeginWithdrawal)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_WITHDRAWAL => {
            Ok(lifecycle::WalletLifecycleEvent::CompleteWithdrawal)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_BEGIN_DELETION => {
            Ok(lifecycle::WalletLifecycleEvent::BeginDeletion)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_COMPLETE_DELETION => {
            Ok(lifecycle::WalletLifecycleEvent::CompleteDeletion)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_MARK_FAILED => {
            Ok(lifecycle::WalletLifecycleEvent::MarkFailed)
        }
        pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_RETRY_PROVISIONING => {
            Ok(lifecycle::WalletLifecycleEvent::RetryProvisioning)
        }
    }
}
