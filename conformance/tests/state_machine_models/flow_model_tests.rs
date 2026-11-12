// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference ledger: only a committed reservation grants an effect capability.

use super::{time, ModelError};
use reallyme_wallet::flows::{
    confirm_flow_effect, create_flow_execution, execution_resume_decision, reserve_flow_effect,
    terminate_flow_execution, ExecutionErrorReason, ExecutionResumeDecision, ReservedFlowEffect,
};
use reallyme_wallet::storage::{
    FlowExecutionStore, StorageError, StorageErrorReason, StorageResult,
};
use reallyme_wallet::types::{
    FlowDisposition, FlowEffectKind, FlowEffectState, FlowExecutionRecord, FlowKind,
    FlowSnapshotId, RecordRevision, Versioned, MAX_FLOW_EFFECTS,
};

const DEADLINE: i64 = 100;

struct Store {
    record: FlowExecutionRecord,
    revision: u64,
    rejection: Option<StorageErrorReason>,
}

impl FlowExecutionStore for Store {
    fn create_execution(&mut self, _: FlowExecutionRecord) -> StorageResult<RecordRevision> {
        Err(StorageError::new(StorageErrorReason::RecordAlreadyExists))
    }
    fn get_execution(&self, _: &FlowSnapshotId) -> StorageResult<Versioned<FlowExecutionRecord>> {
        Ok(Versioned::new(
            self.record.clone(),
            RecordRevision::new(self.revision),
        ))
    }
    fn compare_and_swap_execution(
        &mut self,
        expected: RecordRevision,
        record: FlowExecutionRecord,
    ) -> StorageResult<RecordRevision> {
        if let Some(reason) = self.rejection {
            return Err(StorageError::new(reason));
        }
        if expected.value() != self.revision {
            return Err(StorageError::new(StorageErrorReason::RevisionConflict));
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| StorageError::new(StorageErrorReason::WriteRejected))?;
        self.record = record;
        self.revision = revision;
        Ok(RecordRevision::new(revision))
    }
}

struct Effect {
    id: u8,
    bytes: Vec<u8>,
    kind: FlowEffectKind,
    confirmed: bool,
}

struct Model {
    effects: Vec<Effect>,
    disposition: FlowDisposition,
    updated: i64,
    snapshot: Vec<u8>,
}

impl Model {
    fn before_reservation(&self, now: i64) -> Option<ExecutionErrorReason> {
        if now < self.updated {
            Some(ExecutionErrorReason::TimeRollback)
        } else if self.disposition != FlowDisposition::Active {
            Some(ExecutionErrorReason::Terminal)
        } else if self.effects.iter().any(|effect| !effect.confirmed) {
            Some(ExecutionErrorReason::ReconciliationRequired)
        } else if now >= DEADLINE {
            Some(ExecutionErrorReason::Expired)
        } else {
            None
        }
    }
    fn assert_record(&self, store: &Store) {
        assert_eq!(store.record.disposition, self.disposition);
        assert_eq!(store.record.updated_at.as_seconds(), self.updated);
        assert!(store.record.snapshot == self.snapshot);
        assert_eq!(store.record.effects.len(), self.effects.len());
        for (actual, expected) in store.record.effects.iter().zip(&self.effects) {
            assert_eq!(actual.id, [expected.id; 32]);
            assert!(actual.request_bytes == expected.bytes);
            assert_eq!(actual.kind, expected.kind);
            assert_eq!(
                actual.state == FlowEffectState::Confirmed,
                expected.confirmed
            );
        }
    }
}

pub fn exercise(commands: &[[u8; 4]]) -> Result<(), ModelError> {
    let id = FlowSnapshotId::new("model-flow".into())?;
    let mut store = Store {
        record: FlowExecutionRecord {
            id: id.clone(),
            kind: FlowKind::Presentation,
            intent_digest: [1; 32],
            disposition: FlowDisposition::Active,
            effects: vec![],
            snapshot: vec![1],
            expires_at: time(DEADLINE)?,
            updated_at: time(10)?,
        },
        revision: 1,
        rejection: None,
    };
    let mut model = Model {
        effects: vec![],
        disposition: FlowDisposition::Active,
        updated: 10,
        snapshot: vec![1],
    };
    let mut capability: Option<ReservedFlowEffect> = None;
    for (index, command) in commands.iter().enumerate() {
        let now = if command[3] & 16 != 0 {
            model.updated.checked_sub(1)
        } else {
            i64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(10))
        }
        .ok_or(ModelError::Arithmetic)?;
        store.rejection = match command[3] & 96 {
            32 => Some(StorageErrorReason::WriteRejected),
            64 => Some(StorageErrorReason::RevisionConflict),
            _ => None,
        };
        let before = store.record.clone();
        let revision = store.revision;
        match command[0] % 9 {
            0..=2 => reserve(&mut store, &mut model, &mut capability, command, now)?,
            3 => {
                if let Some(reservation) = capability.take() {
                    confirm(&mut store, &mut model, reservation, command, now)?;
                }
            }
            7 => {
                // Losing an in-memory capability must not erase the committed
                // reservation. Disk/process durability is tested by VaultWallet.
                capability = None;
                let decision = execution_resume_decision(&store.record, time(now)?);
                let expected = if now < model.updated {
                    Err(ExecutionErrorReason::TimeRollback)
                } else if model.disposition != FlowDisposition::Active {
                    Ok(ExecutionResumeDecision::Terminal(model.disposition))
                } else if model.effects.iter().any(|effect| !effect.confirmed) {
                    Ok(ExecutionResumeDecision::ReconcileOnly)
                } else if now >= DEADLINE {
                    Err(ExecutionErrorReason::Expired)
                } else {
                    Ok(ExecutionResumeDecision::Continue)
                };
                assert_eq!(decision.map_err(|error| error.reason), expected);
            }
            opcode => terminate(&mut store, &mut model, opcode, now)?,
        }
        model.assert_record(&store);
        if store.revision == revision {
            assert!(store.record == before);
        }
        assert!(store.record.effects.len() <= MAX_FLOW_EFFECTS);
        assert!(create_flow_execution(&mut store, before).is_err());
    }
    Ok(())
}

fn reserve(
    store: &mut Store,
    model: &mut Model,
    capability: &mut Option<ReservedFlowEffect>,
    command: &[u8; 4],
    now: i64,
) -> Result<(), ModelError> {
    let kind = [
        FlowEffectKind::Signing,
        FlowEffectKind::Submission,
        FlowEffectKind::StorageCommit,
    ][usize::from(command[0] % 3)];
    let id = command[1];
    let bytes = vec![command[2]; usize::from(command[2] % 9)];
    let expected = if bytes.is_empty() || id == 0 {
        Some(ExecutionErrorReason::InvalidRecord)
    } else {
        model
            .before_reservation(now)
            .or_else(|| {
                model
                    .effects
                    .iter()
                    .find(|effect| effect.id == id)
                    .map(|effect| {
                        if effect.bytes == bytes && effect.kind == kind {
                            ExecutionErrorReason::ReconciliationRequired
                        } else {
                            ExecutionErrorReason::IntentConflict
                        }
                    })
            })
            .or_else(|| {
                (model.effects.len() == MAX_FLOW_EFFECTS)
                    .then_some(ExecutionErrorReason::InvalidRecord)
            })
            .or_else(|| store.rejection.map(|_| ExecutionErrorReason::Storage))
    };
    let flow_id = store.record.id.clone();
    let result = reserve_flow_effect(store, &flow_id, [id; 32], bytes.clone(), kind, time(now)?);
    assert_eq!(result.as_ref().err().map(|error| error.reason), expected);
    if let Ok(reservation) = result {
        model.effects.push(Effect {
            id,
            bytes,
            kind,
            confirmed: false,
        });
        model.updated = now;
        *capability = Some(reservation);
    }
    Ok(())
}

fn confirm(
    store: &mut Store,
    model: &mut Model,
    reservation: ReservedFlowEffect,
    command: &[u8; 4],
    now: i64,
) -> Result<(), ModelError> {
    let snapshot = vec![command[2]; usize::from(command[2] % 3)];
    let expected = if snapshot.is_empty() {
        Some(ExecutionErrorReason::InvalidRecord)
    } else if now < model.updated {
        Some(ExecutionErrorReason::TimeRollback)
    } else if model.disposition != FlowDisposition::Active {
        Some(ExecutionErrorReason::Terminal)
    } else {
        store.rejection.map(|_| ExecutionErrorReason::Storage)
    };
    let result = confirm_flow_effect(store, reservation, snapshot.clone(), time(now)?);
    assert_eq!(result.err().map(|error| error.reason), expected);
    if expected.is_none() {
        if let Some(effect) = model.effects.last_mut() {
            effect.confirmed = true;
        }
        model.snapshot = snapshot;
        model.updated = now;
    }
    Ok(())
}

fn terminate(store: &mut Store, model: &mut Model, opcode: u8, now: i64) -> Result<(), ModelError> {
    let requested = match opcode {
        4 => FlowDisposition::Cancelled,
        5 => FlowDisposition::Failed,
        6 => FlowDisposition::Expired,
        _ => FlowDisposition::Completed,
    };
    let delivered = model
        .effects
        .iter()
        .any(|effect| effect.kind != FlowEffectKind::Signing);
    let pending = model.effects.iter().any(|effect| !effect.confirmed);
    let expected = if now < model.updated {
        Err(ExecutionErrorReason::TimeRollback)
    } else if model.disposition != FlowDisposition::Active {
        Ok(model.disposition)
    } else if requested == FlowDisposition::Completed && pending {
        Err(ExecutionErrorReason::ReconciliationRequired)
    } else if (requested == FlowDisposition::Expired && now < DEADLINE)
        || (requested == FlowDisposition::Completed
            && !model
                .effects
                .iter()
                .any(|effect| effect.confirmed && effect.kind == FlowEffectKind::Submission))
    {
        Err(ExecutionErrorReason::InvalidRecord)
    } else if store.rejection.is_some() {
        Err(ExecutionErrorReason::Storage)
    } else if requested != FlowDisposition::Completed && delivered {
        Ok(FlowDisposition::DeliveryUnknown)
    } else {
        Ok(requested)
    };
    let flow_id = store.record.id.clone();
    let result = terminate_flow_execution(store, &flow_id, requested, time(now)?);
    assert_eq!(result.map_err(|error| error.reason), expected);
    if let Ok(disposition) = expected {
        if model.disposition == FlowDisposition::Active {
            model.disposition = disposition;
            model.updated = now;
        }
    }
    Ok(())
}
