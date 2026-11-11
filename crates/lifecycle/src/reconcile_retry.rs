// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bind a provider's safe-to-retry decision to the exact failed operation.

use reallyme_wallet_types::UnixTimestamp;
use zeroize::ZeroizeOnDrop;

use crate::{
    validate_wallet_lifecycle_evidence_record, LifecycleError, LifecycleErrorReason,
    LifecycleResult, WalletLifecycleEvent, WalletLifecycleEvidenceRecord, WalletLifecycleRecord,
    WalletLifecycleState,
};

const MAX_RETRY_EVIDENCE_AGE_SECONDS: i64 = 60;

/// Provider-authenticated reconciliation of one failed recovery or migration.
///
/// Only a trusted provider may construct this receipt, after authenticating
/// the fresh retry evidence and reconciling all partial effects of the failed
/// attempt. Outstanding, completed, or unsafe operations must not produce it.
/// It is intentionally neither serializable nor cloneable authorization.
#[derive(ZeroizeOnDrop)]
pub struct ReconciledWalletLifecycleRetry {
    current: WalletLifecycleRecord,
    evidence: WalletLifecycleEvidenceRecord,
    reconciled_at: UnixTimestamp,
}

/// Whether an event would retry this record's failed recovery or migration.
#[must_use]
pub fn is_wallet_lifecycle_retry(
    current: &WalletLifecycleRecord,
    event: WalletLifecycleEvent,
) -> bool {
    current.state() == WalletLifecycleState::Failed
        && matches!(
            (current.failed_from(), event),
            (
                Some(WalletLifecycleState::RecoveryPending),
                WalletLifecycleEvent::BeginRecovery
            ) | (
                Some(WalletLifecycleState::MigrationPending),
                WalletLifecycleEvent::BeginMigration
            )
        )
}

impl ReconciledWalletLifecycleRetry {
    /// Retain the trusted provider decision for this exact predecessor and retry.
    pub fn new(
        current: WalletLifecycleRecord,
        evidence: WalletLifecycleEvidenceRecord,
        reconciled_at: UnixTimestamp,
    ) -> LifecycleResult<Self> {
        validate_wallet_lifecycle_evidence_record(&evidence)?;
        let failure = current.last_evidence.as_ref().ok_or_else(invalid)?;
        let evidence_age = reconciled_at
            .as_seconds()
            .checked_sub(evidence.occurred_at.as_seconds())
            .ok_or_else(invalid)?;
        if !is_wallet_lifecycle_retry(&current, evidence.event)
            || !matches!(
                current.resume_state(),
                Some(WalletLifecycleState::Active | WalletLifecycleState::Suspended)
            )
            || evidence.wallet_instance_id != *current.wallet_instance_id()
            || evidence.id == failure.id
            || evidence.occurred_at < current.updated_at()
            || evidence.occurred_at > reconciled_at
            || !(0..=MAX_RETRY_EVIDENCE_AGE_SECONDS).contains(&evidence_age)
        {
            return Err(invalid());
        }
        Ok(Self {
            current,
            evidence,
            reconciled_at,
        })
    }

    pub(crate) fn validate(
        &self,
        current: &WalletLifecycleRecord,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> LifecycleResult<()> {
        // The provider may take time to reconcile effects. Recheck freshness
        // after that I/O without requiring both observations to share a second.
        // An exact predecessor/evidence binding and storage CAS prevent reuse.
        let decision_age = now
            .as_seconds()
            .checked_sub(self.reconciled_at.as_seconds())
            .ok_or_else(invalid)?;
        let evidence_age = now
            .as_seconds()
            .checked_sub(evidence.occurred_at.as_seconds())
            .ok_or_else(invalid)?;
        if self.current != *current
            || self.evidence != *evidence
            || !(0..=MAX_RETRY_EVIDENCE_AGE_SECONDS).contains(&decision_age)
            || !(0..=MAX_RETRY_EVIDENCE_AGE_SECONDS).contains(&evidence_age)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> LifecycleError {
    LifecycleError::new(LifecycleErrorReason::InvalidEvidence)
}
