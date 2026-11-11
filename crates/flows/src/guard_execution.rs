// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Write-ahead flow transitions. Never infer safe retry from a missing I/O result.

use reallyme_wallet_storage::{FlowExecutionStore, StorageError, StorageErrorReason};
use reallyme_wallet_types::{
    FlowDisposition, FlowEffect, FlowEffectKind, FlowEffectState, FlowExecutionRecord,
    FlowSnapshotId, RecordRevision, UnixTimestamp, MAX_FLOW_EFFECTS,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum opaque protocol snapshot, validated before allocation by its codec.
pub use reallyme_wallet_types::MAX_EXECUTION_SNAPSHOT_BYTES;
/// Stable disposition/side-effect failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionErrorReason {
    /// Invalid bounded record, binding, or provider response.
    #[error("invalid_record")]
    InvalidRecord,
    /// A terminal flow cannot resume or accept another effect.
    #[error("terminal")]
    Terminal,
    /// A prior reservation requires reconciliation, never a repeated side effect.
    #[error("reconciliation_required")]
    ReconciliationRequired,
    /// The same effect identity was supplied with different bytes or purpose.
    #[error("intent_conflict")]
    IntentConflict,
    /// Trusted time moved backwards.
    #[error("time_rollback")]
    TimeRollback,
    /// Trusted deadline elapsed before reserving a new effect.
    #[error("expired")]
    Expired,
    /// Durable provider failure.
    #[error("storage")]
    Storage,
}
/// Audit-safe flow guard failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("flow execution failed: {reason}")]
pub struct ExecutionError {
    /// Fixed domain reason.
    pub reason: ExecutionErrorReason,
    /// Fixed provider reason, if applicable.
    pub storage_reason: Option<StorageErrorReason>,
}
impl From<StorageError> for ExecutionError {
    fn from(error: StorageError) -> Self {
        Self {
            reason: ExecutionErrorReason::Storage,
            storage_reason: Some(error.reason),
        }
    }
}
fn error(reason: ExecutionErrorReason) -> ExecutionError {
    ExecutionError {
        reason,
        storage_reason: None,
    }
}
/// Single-use capability proving the write-ahead effect reservation committed.
#[derive(ZeroizeOnDrop)]
pub struct ReservedFlowEffect {
    flow_id: FlowSnapshotId,
    effect_id: [u8; 32],
    request_digest: [u8; 32],
    intent_digest: [u8; 32],
}
impl ReservedFlowEffect {
    /// Digest of the exact canonical operation envelope durably reserved.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

/// Resume result; uncertain work cannot produce another reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionResumeDecision {
    /// No side effect is outstanding, so a new distinct effect may be reserved.
    Continue,
    /// Host must reconcile the original exact request; it must not resend it.
    ReconcileOnly,
    /// Terminal disposition; no further side effects are authorized.
    Terminal(FlowDisposition),
}
/// Validate state before restoring or persisting it.
pub fn validate_execution_record(record: &FlowExecutionRecord) -> Result<(), ExecutionError> {
    if record.id.as_str().is_empty()
        || record.intent_digest == [0; 32]
        || (record.expires_at <= record.updated_at
            && record.disposition == FlowDisposition::Active
            && !record
                .effects
                .last()
                .is_some_and(|effect| effect.state == FlowEffectState::Confirmed))
        || record.effects.len() > MAX_FLOW_EFFECTS
        || record.snapshot.is_empty()
        || record.snapshot.len() > MAX_EXECUTION_SNAPSHOT_BYTES
    {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    let total = record
        .effects
        .iter()
        .try_fold(0_usize, |total, effect| {
            if effect.request_bytes.is_empty()
                || effect.request_bytes.len() > reallyme_wallet_types::MAX_FLOW_EFFECT_BYTES
            {
                return None;
            }
            total.checked_add(effect.request_bytes.len())
        })
        .ok_or_else(|| error(ExecutionErrorReason::InvalidRecord))?;
    if total > reallyme_wallet_types::MAX_FLOW_EFFECT_TOTAL_BYTES {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut reserved = 0_usize;
    for effect in &record.effects {
        if crypto_sha2_256::digest(&effect.request_bytes).into_bytes() != effect.request_digest
            || effect.id == [0; 32]
            || effect.request_digest == [0; 32]
            || !ids.insert(&effect.id)
        {
            return Err(error(ExecutionErrorReason::InvalidRecord));
        }
        if effect.state == FlowEffectState::Reserved {
            reserved = reserved
                .checked_add(1)
                .ok_or_else(|| error(ExecutionErrorReason::InvalidRecord))?;
        }
    }
    if reserved > 1
        || (record.disposition == FlowDisposition::Completed && reserved != 0)
        || (reserved > 0
            && record
                .effects
                .last()
                .is_none_or(|effect| effect.state != FlowEffectState::Reserved))
    {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    let possible_delivery = record.effects.iter().any(|effect| {
        matches!(
            effect.kind,
            FlowEffectKind::Submission | FlowEffectKind::StorageCommit
        )
    });
    let completed_effect = record.effects.iter().any(|effect| {
        effect.state == FlowEffectState::Confirmed
            && match record.kind {
                reallyme_wallet_types::FlowKind::Issuance => {
                    effect.kind == FlowEffectKind::StorageCommit
                }
                reallyme_wallet_types::FlowKind::Presentation => {
                    effect.kind == FlowEffectKind::Submission
                }
            }
    });
    if (record.disposition == FlowDisposition::DeliveryUnknown && !possible_delivery)
        || (matches!(
            record.disposition,
            FlowDisposition::Cancelled | FlowDisposition::Failed | FlowDisposition::Expired
        ) && possible_delivery)
        || (record.disposition == FlowDisposition::Completed && !completed_effect)
    {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    Ok(())
}
/// Initialize a guard before any consent, signing, or external I/O occurs.
pub fn create_flow_execution(
    store: &mut dyn FlowExecutionStore,
    record: FlowExecutionRecord,
) -> Result<RecordRevision, ExecutionError> {
    validate_execution_record(&record)?;
    if record.disposition != FlowDisposition::Active || !record.effects.is_empty() {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    Ok(store.create_execution(record)?)
}
/// Decide whether a restored flow may continue, using explicit trusted time.
pub fn execution_resume_decision(
    record: &FlowExecutionRecord,
    now: UnixTimestamp,
) -> Result<ExecutionResumeDecision, ExecutionError> {
    validate_execution_record(record)?;
    if now < record.updated_at {
        return Err(error(ExecutionErrorReason::TimeRollback));
    }
    if record.disposition != FlowDisposition::Active {
        return Ok(ExecutionResumeDecision::Terminal(record.disposition));
    }
    if record
        .effects
        .iter()
        .any(|effect| effect.state == FlowEffectState::Reserved)
    {
        return Ok(ExecutionResumeDecision::ReconcileOnly);
    }
    if now >= record.expires_at {
        return Err(error(ExecutionErrorReason::Expired));
    }
    Ok(ExecutionResumeDecision::Continue)
}
/// Commit one exact effect before invoking its provider. A concurrent cancellation
/// wins or loses at this CAS; there is no unlocked check-then-send interval.
pub fn reserve_flow_effect(
    store: &mut dyn FlowExecutionStore,
    flow_id: &FlowSnapshotId,
    effect_id: [u8; 32],
    request_bytes: Vec<u8>,
    kind: FlowEffectKind,
    now: UnixTimestamp,
) -> Result<ReservedFlowEffect, ExecutionError> {
    let mut request_bytes = zeroize::Zeroizing::new(request_bytes);
    if request_bytes.is_empty()
        || request_bytes.len() > reallyme_wallet_types::MAX_FLOW_EFFECT_BYTES
    {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    let request_digest = crypto_sha2_256::digest(&request_bytes).into_bytes();
    let (mut record, revision) = store.get_execution(flow_id)?.into_parts();
    if &record.id != flow_id || effect_id == [0; 32] || request_digest == [0; 32] {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    match execution_resume_decision(&record, now)? {
        ExecutionResumeDecision::Continue => {}
        ExecutionResumeDecision::ReconcileOnly => {
            return Err(error(ExecutionErrorReason::ReconciliationRequired))
        }
        ExecutionResumeDecision::Terminal(_) => return Err(error(ExecutionErrorReason::Terminal)),
    }
    if let Some(prior) = record.effects.iter().find(|effect| effect.id == effect_id) {
        return Err(error(
            if prior.request_digest == request_digest && prior.kind == kind {
                ExecutionErrorReason::ReconciliationRequired
            } else {
                ExecutionErrorReason::IntentConflict
            },
        ));
    }
    if record.effects.len() == MAX_FLOW_EFFECTS {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    let total = record
        .effects
        .iter()
        .try_fold(request_bytes.len(), |total, effect| {
            total.checked_add(effect.request_bytes.len())
        })
        .ok_or_else(|| error(ExecutionErrorReason::InvalidRecord))?;
    if total > reallyme_wallet_types::MAX_FLOW_EFFECT_TOTAL_BYTES {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    record.effects.push(FlowEffect {
        request_bytes: core::mem::take(&mut *request_bytes),
        id: effect_id,
        request_digest,
        kind,
        state: FlowEffectState::Reserved,
    });
    record.updated_at = now;
    let intent_digest = record.intent_digest;
    let committed = store.compare_and_swap_execution(revision, record)?;
    if committed <= revision {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    Ok(ReservedFlowEffect {
        flow_id: flow_id.clone(),
        effect_id,
        request_digest,
        intent_digest,
    })
}
/// Confirm an effect and its protocol snapshot together. The capability is
/// consumed; a failed write requires reconciliation of the retained reservation.
pub fn confirm_flow_effect(
    store: &mut dyn FlowExecutionStore,
    reservation: ReservedFlowEffect,
    snapshot: Vec<u8>,
    now: UnixTimestamp,
) -> Result<RecordRevision, ExecutionError> {
    let mut snapshot = zeroize::Zeroizing::new(snapshot);
    // An empty snapshot would make the stored record fail validation on every
    // later read and strand the flow, so reject it before writing.
    if snapshot.is_empty() || snapshot.len() > MAX_EXECUTION_SNAPSHOT_BYTES {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    let (mut record, revision) = store.get_execution(&reservation.flow_id)?.into_parts();
    validate_execution_record(&record)?;
    if record.id != reservation.flow_id || record.intent_digest != reservation.intent_digest {
        return Err(error(ExecutionErrorReason::IntentConflict));
    }
    if now < record.updated_at {
        return Err(error(ExecutionErrorReason::TimeRollback));
    }
    if record.disposition != FlowDisposition::Active {
        return Err(error(ExecutionErrorReason::Terminal));
    }
    let effect = record
        .effects
        .last_mut()
        .ok_or_else(|| error(ExecutionErrorReason::InvalidRecord))?;
    if effect.id != reservation.effect_id
        || effect.request_digest != reservation.request_digest
        || effect.state != FlowEffectState::Reserved
    {
        return Err(error(ExecutionErrorReason::IntentConflict));
    }
    // An effect already in flight can complete after the deadline. Its result
    // is now known and must be retained, and the disposition stays active so
    // a confirmed submission can still be terminated as completed. Only the
    // last effect can be reserved, so no other delivery remains uncertain; the
    // next reserve observes expiry and fails closed.
    effect.state = FlowEffectState::Confirmed;
    record.snapshot.zeroize();
    record.snapshot = core::mem::take(&mut *snapshot);
    record.updated_at = now;
    let committed = store.compare_and_swap_execution(revision, record)?;
    if committed <= revision {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    Ok(committed)
}
/// Persist cancellation, failure, expiry, or completion. A possible submission
/// is recorded as uncertain even when the host asks to cancel. No copy is freed.
pub fn terminate_flow_execution(
    store: &mut dyn FlowExecutionStore,
    flow_id: &FlowSnapshotId,
    requested: FlowDisposition,
    now: UnixTimestamp,
) -> Result<FlowDisposition, ExecutionError> {
    let (mut record, revision) = store.get_execution(flow_id)?.into_parts();
    validate_execution_record(&record)?;
    if &record.id != flow_id
        || requested == FlowDisposition::Active
        || requested == FlowDisposition::DeliveryUnknown
    {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    if now < record.updated_at {
        return Err(error(ExecutionErrorReason::TimeRollback));
    }
    if record.disposition != FlowDisposition::Active {
        return Ok(record.disposition);
    }
    let pending = record
        .effects
        .iter()
        .any(|effect| effect.state == FlowEffectState::Reserved);
    let possible_delivery = record.effects.iter().any(|effect| {
        matches!(
            effect.kind,
            FlowEffectKind::Submission | FlowEffectKind::StorageCommit
        )
    });
    if requested == FlowDisposition::Completed && pending {
        return Err(error(ExecutionErrorReason::ReconciliationRequired));
    }
    if requested == FlowDisposition::Expired && now < record.expires_at {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    if requested == FlowDisposition::Completed {
        let completed_effect = record.effects.iter().any(|effect| {
            effect.state == FlowEffectState::Confirmed
                && match record.kind {
                    reallyme_wallet_types::FlowKind::Issuance => {
                        effect.kind == FlowEffectKind::StorageCommit
                    }
                    reallyme_wallet_types::FlowKind::Presentation => {
                        effect.kind == FlowEffectKind::Submission
                    }
                }
        });
        if !completed_effect {
            return Err(error(ExecutionErrorReason::InvalidRecord));
        }
    }
    let disposition = if requested != FlowDisposition::Completed && possible_delivery {
        FlowDisposition::DeliveryUnknown
    } else {
        requested
    };
    record.disposition = disposition;
    record.updated_at = now;
    let committed = store.compare_and_swap_execution(revision, record)?;
    if committed <= revision {
        return Err(error(ExecutionErrorReason::InvalidRecord));
    }
    Ok(disposition)
}
#[cfg(test)]
#[path = "guard_execution_tests.rs"]
mod tests;
