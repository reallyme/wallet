// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    confirm_flow_effect, create_flow_execution, execution_resume_decision, reserve_flow_effect,
    terminate_flow_execution, ExecutionError, ExecutionErrorReason, ExecutionResumeDecision,
};
use reallyme_wallet_storage::{
    FlowExecutionStore, StorageError, StorageErrorReason, StorageResult,
};
use reallyme_wallet_types::{
    FlowDisposition, FlowEffectKind, FlowExecutionRecord, FlowKind, FlowSnapshotId, RecordRevision,
    UnixTimestamp, Versioned, WalletTypesError,
};
use thiserror::Error;
#[derive(Default)]
struct Store {
    record: Option<FlowExecutionRecord>,
    generation: u64,
    fail: bool,
}
impl FlowExecutionStore for Store {
    fn create_execution(&mut self, r: FlowExecutionRecord) -> StorageResult<RecordRevision> {
        if self.record.is_some() {
            return Err(StorageError::new(StorageErrorReason::RecordAlreadyExists));
        }
        self.record = Some(r);
        self.generation = 1;
        Ok(RecordRevision::new(1))
    }
    fn get_execution(&self, _: &FlowSnapshotId) -> StorageResult<Versioned<FlowExecutionRecord>> {
        Ok(Versioned::new(
            self.record
                .clone()
                .ok_or(StorageError::new(StorageErrorReason::RecordNotFound))?,
            RecordRevision::new(self.generation),
        ))
    }
    fn compare_and_swap_execution(
        &mut self,
        expected: RecordRevision,
        r: FlowExecutionRecord,
    ) -> StorageResult<RecordRevision> {
        if expected.value() != self.generation {
            return Err(StorageError::new(StorageErrorReason::RevisionConflict));
        }
        if self.fail {
            return Err(StorageError::new(StorageErrorReason::WriteRejected));
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(StorageError::new(StorageErrorReason::WriteRejected))?;
        self.record = Some(r);
        Ok(RecordRevision::new(self.generation))
    }
}
fn time(n: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(n)
}

#[test]
fn accepted_submission_with_failed_confirmation_requires_reconciliation_after_restart(
) -> Result<(), TestError> {
    let mut store = Store::default();
    let record = record()?;
    let id = record.id.clone();
    create_flow_execution(&mut store, record)?;
    let exact_request = vec![0x31, 0x32, 0x33];
    let reservation = reserve_flow_effect(
        &mut store,
        &id,
        [2; 32],
        exact_request.clone(),
        FlowEffectKind::Submission,
        time(20)?,
    )?;
    // Model a remote acceptance followed by failure to durably acknowledge it.
    // A missing local confirmation is not evidence that the remote effect failed.
    store.fail = true;
    assert_eq!(
        confirm_flow_effect(&mut store, reservation, vec![9], time(21)?)
            .err()
            .map(|error| error.reason),
        Some(ExecutionErrorReason::Storage)
    );
    let mut restarted = Store {
        record: store.record.clone(),
        generation: store.generation,
        fail: false,
    };
    let persisted = restarted.get_execution(&id)?.into_parts().0;
    assert_eq!(persisted.snapshot, vec![1]);
    assert_eq!(persisted.effects.len(), 1);
    assert_eq!(persisted.effects[0].request_bytes, exact_request);
    assert_eq!(
        execution_resume_decision(&persisted, time(22)?)?,
        ExecutionResumeDecision::ReconcileOnly
    );
    assert_eq!(
        reserve_flow_effect(
            &mut restarted,
            &id,
            [2; 32],
            exact_request,
            FlowEffectKind::Submission,
            time(22)?
        )
        .err()
        .map(|error| error.reason),
        Some(ExecutionErrorReason::ReconciliationRequired)
    );
    assert_eq!(
        terminate_flow_execution(&mut restarted, &id, FlowDisposition::Failed, time(23)?)?,
        FlowDisposition::DeliveryUnknown
    );
    Ok(())
}
fn record() -> Result<FlowExecutionRecord, WalletTypesError> {
    Ok(FlowExecutionRecord {
        id: FlowSnapshotId::new("flow".into())?,
        kind: FlowKind::Presentation,
        intent_digest: [1; 32],
        disposition: FlowDisposition::Active,
        effects: vec![],
        snapshot: vec![1],
        expires_at: time(100)?,
        updated_at: time(10)?,
    })
}
#[test]
fn reserved_submission_survives_restart_and_becomes_uncertain_on_cancel() -> Result<(), TestError> {
    let mut s = Store::default();
    let r = record()?;
    let id = r.id.clone();
    create_flow_execution(&mut s, r)?;
    let reservation = reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![3],
        FlowEffectKind::Submission,
        time(20)?,
    )?;
    let mut restarted = Store {
        record: s.record.clone(),
        generation: s.generation,
        fail: false,
    };
    assert_eq!(
        reserve_flow_effect(
            &mut restarted,
            &id,
            [2; 32],
            vec![3],
            FlowEffectKind::Submission,
            time(21)?
        )
        .err()
        .map(|e| e.reason),
        Some(ExecutionErrorReason::ReconciliationRequired)
    );
    assert_eq!(
        terminate_flow_execution(&mut restarted, &id, FlowDisposition::Cancelled, time(21)?)?,
        FlowDisposition::DeliveryUnknown
    );
    assert!(confirm_flow_effect(&mut restarted, reservation, vec![2], time(22)?).is_err());
    assert_eq!(
        reserve_flow_effect(
            &mut restarted,
            &id,
            [4; 32],
            vec![3],
            FlowEffectKind::Signing,
            time(22)?
        )
        .err()
        .map(|e| e.reason),
        Some(ExecutionErrorReason::Terminal)
    );
    Ok(())
}
#[test]
fn cancellation_wins_before_reservation_and_terminals_are_idempotent() -> Result<(), TestError> {
    for disposition in [
        FlowDisposition::Cancelled,
        FlowDisposition::Failed,
        FlowDisposition::Expired,
    ] {
        let mut s = Store::default();
        let r = record()?;
        let id = r.id.clone();
        create_flow_execution(&mut s, r)?;
        let now = if disposition == FlowDisposition::Expired {
            100
        } else {
            20
        };
        assert_eq!(
            terminate_flow_execution(&mut s, &id, disposition, time(now)?)?,
            disposition
        );
        assert_eq!(
            terminate_flow_execution(&mut s, &id, FlowDisposition::Cancelled, time(now)?)?,
            disposition
        );
        assert!(reserve_flow_effect(
            &mut s,
            &id,
            [2; 32],
            vec![3],
            FlowEffectKind::Signing,
            time(now)?
        )
        .is_err());
    }
    Ok(())
}
#[test]
fn failed_writes_do_not_authorize_effects_and_expiry_is_exclusive() -> Result<(), TestError> {
    let mut s = Store::default();
    let r = record()?;
    let id = r.id.clone();
    create_flow_execution(&mut s, r)?;
    s.fail = true;
    assert!(reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![3],
        FlowEffectKind::Signing,
        time(20)?
    )
    .is_err());
    assert!(s.record.as_ref().is_some_and(|r| r.effects.is_empty()));
    s.fail = false;
    assert_eq!(
        reserve_flow_effect(
            &mut s,
            &id,
            [2; 32],
            vec![3],
            FlowEffectKind::Signing,
            time(100)?
        )
        .err()
        .map(|e| e.reason),
        Some(ExecutionErrorReason::Expired)
    );
    assert!(reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![3],
        FlowEffectKind::Signing,
        time(9)?
    )
    .is_err());
    Ok(())
}
#[test]
fn confirmation_commits_snapshot_and_prevents_repeated_effect() -> Result<(), TestError> {
    let mut s = Store::default();
    let r = record()?;
    let id = r.id.clone();
    create_flow_execution(&mut s, r)?;
    let cap = reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![3],
        FlowEffectKind::Submission,
        time(20)?,
    )?;
    confirm_flow_effect(&mut s, cap, vec![9], time(21)?)?;
    let (r, _) = s.get_execution(&id)?.into_parts();
    assert_eq!(r.snapshot, vec![9]);
    assert_eq!(
        execution_resume_decision(&r, time(21)?)?,
        ExecutionResumeDecision::Continue
    );
    assert!(reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![4],
        FlowEffectKind::Submission,
        time(22)?
    )
    .is_err());
    assert_eq!(
        terminate_flow_execution(&mut s, &id, FlowDisposition::Completed, time(22)?)?,
        FlowDisposition::Completed
    );
    Ok(())
}
#[derive(Debug, Error)]
enum TestError {
    #[error("missing_effect")]
    MissingEffect,
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("execution")]
    Execution(#[from] ExecutionError),
    #[error("storage")]
    Storage(#[from] StorageError),
}

#[test]
fn reservations_retain_exact_bytes_and_bound_total_material() -> Result<(), TestError> {
    let mut store = Store::default();
    let original = record()?;
    let id = original.id.clone();
    create_flow_execution(&mut store, original)?;
    for value in [2_u8, 3_u8] {
        let cap = reserve_flow_effect(
            &mut store,
            &id,
            [value; 32],
            vec![value; reallyme_wallet_types::MAX_FLOW_EFFECT_BYTES],
            FlowEffectKind::Signing,
            time(20)?,
        )?;
        let (reserved, _) = store.get_execution(&id)?.into_parts();
        let effect = reserved.effects.last().ok_or(TestError::MissingEffect)?;
        assert_eq!(
            effect.request_bytes.len(),
            reallyme_wallet_types::MAX_FLOW_EFFECT_BYTES
        );
        assert_eq!(effect.request_digest, *cap.request_digest());
        confirm_flow_effect(&mut store, cap, vec![1], time(20)?)?;
    }
    assert_eq!(
        reserve_flow_effect(
            &mut store,
            &id,
            [4; 32],
            vec![4],
            FlowEffectKind::Signing,
            time(20)?
        )
        .err()
        .map(|e| e.reason),
        Some(ExecutionErrorReason::InvalidRecord)
    );
    assert!(
        terminate_flow_execution(&mut store, &id, FlowDisposition::Completed, time(20)?).is_err()
    );
    assert_eq!(
        terminate_flow_execution(&mut store, &id, FlowDisposition::Cancelled, time(20)?)?,
        FlowDisposition::Cancelled
    );
    Ok(())
}

#[test]
fn confirmation_rejects_an_empty_snapshot() -> Result<(), TestError> {
    let mut s = Store::default();
    let r = record()?;
    let id = r.id.clone();
    create_flow_execution(&mut s, r)?;
    let cap = reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![3],
        FlowEffectKind::Submission,
        time(20)?,
    )?;
    assert!(matches!(
        confirm_flow_effect(&mut s, cap, Vec::new(), time(21)?),
        Err(error) if error.reason == ExecutionErrorReason::InvalidRecord
    ));
    let (stored, _) = s.get_execution(&id)?.into_parts();
    assert_eq!(stored.snapshot, vec![1]);
    Ok(())
}

#[test]
fn delivery_confirmed_after_the_deadline_can_still_complete() -> Result<(), TestError> {
    let mut s = Store::default();
    let r = record()?;
    let id = r.id.clone();
    create_flow_execution(&mut s, r)?;
    let cap = reserve_flow_effect(
        &mut s,
        &id,
        [2; 32],
        vec![3],
        FlowEffectKind::Submission,
        time(99)?,
    )?;
    confirm_flow_effect(&mut s, cap, vec![9], time(101)?)?;
    assert!(reserve_flow_effect(
        &mut s,
        &id,
        [5; 32],
        vec![6],
        FlowEffectKind::Submission,
        time(102)?
    )
    .is_err());
    assert_eq!(
        terminate_flow_execution(&mut s, &id, FlowDisposition::Completed, time(102)?)?,
        FlowDisposition::Completed
    );
    Ok(())
}
