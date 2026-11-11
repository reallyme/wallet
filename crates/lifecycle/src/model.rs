// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lifecycle records and enums.

use reallyme_wallet_types::{NonEmptyIdentifier, UnixTimestamp};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Durable Wallet Unit lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum WalletLifecycleState {
    /// Wallet identity and secure-area state have not been provisioned.
    Unprovisioned,
    /// Provisioning is in progress and may need to resume after interruption.
    Provisioning,
    /// Wallet is provisioned and may perform credential and presentation work.
    Active,
    /// Wallet is intentionally disabled but local records remain available.
    Suspended,
    /// Recovery is in progress and active signing/presentation is blocked.
    RecoveryPending,
    /// Migration is in progress and active signing/presentation is blocked.
    MigrationPending,
    /// Withdrawal is in progress and active signing/presentation is blocked.
    WithdrawalPending,
    /// Deletion is in progress and active signing/presentation is blocked.
    DeletionPending,
    /// Wallet has been withdrawn and must not perform new regulated actions.
    Withdrawn,
    /// Wallet has been deleted and must not perform new regulated actions.
    Deleted,
    /// Lifecycle failed during a recoverable operation.
    Failed,
}

/// Input event that advances the durable lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum WalletLifecycleEvent {
    /// Start wallet provisioning.
    BeginProvisioning,
    /// Complete provisioning and activate the wallet.
    CompleteProvisioning,
    /// Suspend active wallet use.
    Suspend,
    /// Reactivate a suspended wallet.
    Reactivate,
    /// Start recovery.
    BeginRecovery,
    /// Complete recovery and reactivate the wallet.
    CompleteRecovery,
    /// Start migration.
    BeginMigration,
    /// Complete migration and reactivate the wallet.
    CompleteMigration,
    /// Start withdrawal.
    BeginWithdrawal,
    /// Complete withdrawal.
    CompleteWithdrawal,
    /// Start deletion.
    BeginDeletion,
    /// Complete deletion.
    CompleteDeletion,
    /// Mark the current pending operation as failed.
    MarkFailed,
    /// Retry provisioning from a failed state.
    RetryProvisioning,
}

/// Wallet lifecycle operation that needs durable audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum WalletLifecycleEvidenceKind {
    /// Wallet provisioning evidence.
    Provisioning,
    /// Wallet backup evidence produced by an SDK/provider.
    Backup,
    /// Wallet restore evidence produced by an SDK/provider.
    Restore,
    /// Wallet recovery evidence.
    Recovery,
    /// Wallet migration evidence.
    Migration,
    /// Portability export evidence.
    PortabilityExport,
    /// Portability import evidence.
    PortabilityImport,
    /// Wallet withdrawal evidence.
    Withdrawal,
    /// Wallet deletion evidence.
    Deletion,
    /// Wallet suspension evidence.
    Suspension,
    /// Wallet reactivation evidence.
    Reactivation,
}

/// Durable lifecycle record stored by the platform SDK.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WalletLifecycleRecord {
    /// Stable wallet instance identifier.
    pub(crate) wallet_instance_id: NonEmptyIdentifier,
    /// Current lifecycle state.
    pub(crate) state: WalletLifecycleState,
    /// Last lifecycle update timestamp.
    pub(crate) updated_at: UnixTimestamp,
    /// Event that produced the current state, absent only for a new record.
    pub(crate) last_event: Option<WalletLifecycleEvent>,
    /// State to restore after recovery or migration completes.
    pub(crate) resume_state: Option<WalletLifecycleState>,
    /// Pending operation that entered the generic failure state.
    pub(crate) failed_from: Option<WalletLifecycleState>,
    /// Evidence retained atomically with the state transition.
    pub(crate) last_evidence: Option<WalletLifecycleEvidenceRecord>,
}

impl core::fmt::Debug for WalletLifecycleRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WalletLifecycleRecord")
            .field("wallet_instance_id", &self.wallet_instance_id)
            .field("state", &self.state)
            .field("updated_at", &self.updated_at)
            .field("last_event", &self.last_event)
            .field("resume_state", &self.resume_state)
            .field("failed_from", &self.failed_from)
            .field(
                "last_evidence",
                &self.last_evidence.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl WalletLifecycleRecord {
    /// Stable wallet instance identifier.
    #[must_use]
    pub const fn wallet_instance_id(&self) -> &NonEmptyIdentifier {
        &self.wallet_instance_id
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> WalletLifecycleState {
        self.state
    }

    /// Last lifecycle update timestamp.
    #[must_use]
    pub const fn updated_at(&self) -> UnixTimestamp {
        self.updated_at
    }

    /// Event that produced the current state.
    #[must_use]
    pub const fn last_event(&self) -> Option<WalletLifecycleEvent> {
        self.last_event
    }

    /// State restored after a pending recovery or migration.
    #[must_use]
    pub const fn resume_state(&self) -> Option<WalletLifecycleState> {
        self.resume_state
    }

    /// Pending state from which a failure was recorded.
    #[must_use]
    pub const fn failed_from(&self) -> Option<WalletLifecycleState> {
        self.failed_from
    }

    /// Evidence that authorized the last state transition.
    #[must_use]
    pub const fn last_evidence(&self) -> Option<&WalletLifecycleEvidenceRecord> {
        self.last_evidence.as_ref()
    }
}

/// Durable lifecycle evidence record supplied by SDK/provider adapters.
///
/// Wallet-core stores only bounded metadata and a digest of provider evidence.
/// Cloud backup payloads, device-local secure-area receipts, and user-facing
/// recovery UX stay outside this crate.
///
/// Provider references and evidence digests are redacted from `Debug` and
/// wiped with the rest of the record on drop.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WalletLifecycleEvidenceRecord {
    /// Stable evidence identifier.
    pub id: NonEmptyIdentifier,
    /// Wallet instance this evidence belongs to.
    pub wallet_instance_id: NonEmptyIdentifier,
    /// Lifecycle operation evidenced by this record.
    pub kind: WalletLifecycleEvidenceKind,
    /// Lifecycle event this evidence supports.
    pub event: WalletLifecycleEvent,
    /// Time the evidenced operation occurred.
    pub occurred_at: UnixTimestamp,
    /// SDK/provider authority that produced the evidence.
    pub authority_id: NonEmptyIdentifier,
    /// Non-secret provider reference for retrieving full evidence if allowed.
    pub evidence_ref: NonEmptyIdentifier,
    /// Digest of the provider evidence; wallet-core never stores raw payloads.
    pub evidence_digest: Vec<u8>,
}

/// Regulated wallet operation checked against lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletOperation {
    /// Begin or resume credential issuance.
    BeginIssuance,
    /// Produce a presentation response.
    PresentCredential,
    /// Use a wallet-held key for a regulated wallet action.
    SignWithWalletKey,
    /// Refresh credential status evidence.
    RefreshCredentialStatus,
    /// Read user-visible transaction history.
    ReadTransactionHistory,
    /// Append an entry to the user-visible transaction history.
    ///
    /// Withdrawn and deleted Wallet Units record no new history.
    RecordTransactionHistory,
    /// Begin wallet deletion, or erase records once deletion has completed.
    DeleteWallet,
    /// Obtain or rotate Wallet Unit Attestation.
    RenewAttestation,
    /// Read stored credential records and resumable flow snapshots.
    ///
    /// Withdrawn and deleted Wallet Units no longer expose credential payloads
    /// or flow state, and neither does a unit whose withdrawal or deletion has
    /// begun; only transaction history stays readable.
    ReadWalletRecords,
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
