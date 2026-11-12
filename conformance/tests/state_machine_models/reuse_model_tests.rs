// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Allocation is checked against a small independent operation/slot ledger.

use super::{time, ModelError};
use reallyme_wallet::inventory::{
    claim_credential_use, evaluate_replenishment, fulfill_replenishment, request_replenishment,
    ReplenishmentDecision, ReuseErrorReason,
};
use reallyme_wallet::storage::{
    CredentialReuseStore, StorageError, StorageErrorReason, StorageResult,
};
use reallyme_wallet::types::{
    CredentialReuseMethod as Method, CredentialReusePolicySelection, CredentialReuseState,
    NonEmptyIdentifier, RecordRevision, ReuseInstance, Versioned,
};
use std::collections::BTreeMap;

const METHODS: [Method; 5] = [
    Method::Unrestricted,
    Method::OnceOnly,
    Method::LimitedTime,
    Method::RotatingBatch,
    Method::PerRelyingParty,
];
const EXPIRY: i64 = 100;

struct Store {
    state: CredentialReuseState,
    replacement: Option<CredentialReuseState>,
    revision: u64,
    rejection: Option<StorageErrorReason>,
}
impl CredentialReuseStore for Store {
    fn create_reuse_state(&mut self, _: CredentialReuseState) -> StorageResult<RecordRevision> {
        Err(StorageError::new(StorageErrorReason::RecordAlreadyExists))
    }
    fn get_reuse_state(
        &self,
        _: &NonEmptyIdentifier,
    ) -> StorageResult<Versioned<CredentialReuseState>> {
        Ok(Versioned::new(
            self.state.clone(),
            RecordRevision::new(self.revision),
        ))
    }
    fn compare_and_swap_reuse_state(
        &mut self,
        expected: RecordRevision,
        state: CredentialReuseState,
    ) -> StorageResult<RecordRevision> {
        if let Some(reason) = self.rejection {
            return Err(StorageError::new(reason));
        }
        if expected.value() != self.revision {
            return Err(StorageError::new(StorageErrorReason::RevisionConflict));
        }
        let next = self
            .revision
            .checked_add(1)
            .ok_or_else(|| StorageError::new(StorageErrorReason::WriteRejected))?;
        self.state = state;
        self.revision = next;
        Ok(RecordRevision::new(next))
    }
    fn commit_replenishment(
        &mut self,
        revision: RecordRevision,
        retired: CredentialReuseState,
        replacement: CredentialReuseState,
    ) -> StorageResult<RecordRevision> {
        let next = self.compare_and_swap_reuse_state(revision, retired)?;
        self.replacement = Some(replacement);
        Ok(next)
    }
}

struct Model {
    claims: BTreeMap<u8, (u8, u8, usize)>,
    uses: [u64; 4],
    parties: [Option<u8>; 4],
    next_slot: usize,
    updated: i64,
    retired: bool,
    replenishment: Option<u8>,
}
impl Model {
    fn select(&self, method: Method, party: u8) -> Option<usize> {
        match method {
            Method::OnceOnly => self.uses.iter().position(|uses| *uses == 0),
            Method::PerRelyingParty => self
                .parties
                .iter()
                .position(|assigned| *assigned == Some(party))
                .or_else(|| self.parties.iter().position(Option::is_none)),
            Method::RotatingBatch => Some(self.next_slot),
            Method::Unrestricted | Method::LimitedTime => Some(0),
        }
    }
    fn decision(&self, method: Method, now: i64) -> ReplenishmentDecision {
        if now >= EXPIRY || (method == Method::OnceOnly && self.uses.iter().all(|uses| *uses > 0)) {
            ReplenishmentDecision::Exhausted
        } else if method == Method::PerRelyingParty && self.parties.iter().all(Option::is_some) {
            ReplenishmentDecision::PartyCapacity
        } else if method == Method::OnceOnly
            && self.uses.iter().filter(|uses| **uses == 0).count() <= 1
        {
            ReplenishmentDecision::UnusedThreshold
        } else if matches!(
            method,
            Method::LimitedTime | Method::RotatingBatch | Method::PerRelyingParty
        ) && now >= EXPIRY - 5
        {
            ReplenishmentDecision::LifetimeThreshold
        } else {
            ReplenishmentDecision::NotRequired
        }
    }
    fn assert_state(&self, store: &Store) {
        assert_eq!(store.state.claims.len(), self.claims.len());
        assert_eq!(store.state.instances.len(), self.uses.len());
        assert_eq!(
            usize::try_from(store.state.next_index).ok(),
            Some(self.next_slot)
        );
        assert_eq!(store.state.retired, self.retired);
        assert_eq!(store.state.updated_at.as_seconds(), self.updated);
        assert_eq!(store.replacement.is_some(), self.retired);
        if let Some(replacement) = &store.replacement {
            assert_eq!(replacement.id.as_str(), "replacement");
            assert!(!replacement.retired);
            assert!(replacement.claims.is_empty());
            assert!(replacement.replenishment.is_none());
            assert_eq!(replacement.next_index, 0);
            assert_eq!(replacement.updated_at.as_seconds(), self.updated);
            assert_eq!(replacement.instances.len(), self.uses.len());
            assert!(replacement.instances.iter().all(|instance| {
                instance.uses == 0 && !instance.retired && instance.party_binding.is_none()
            }));
        }
        for ((actual, uses), party) in store
            .state
            .instances
            .iter()
            .zip(self.uses)
            .zip(self.parties)
        {
            assert_eq!(actual.uses, uses);
            assert_eq!(actual.party_binding, party.map(|value| [value; 32]));
        }
        for (operation, (digest, party, slot)) in &self.claims {
            let actual = store
                .state
                .claims
                .iter()
                .find(|claim| claim.operation_id == [*operation; 32]);
            assert!(
                actual.is_some_and(|claim| claim.request_digest == [*digest; 32]
                    && claim.party_binding == [*party; 32]
                    && claim.credential_id == store.state.instances[*slot].credential_id)
            );
        }
    }
}

fn cohort(method: Method, id: &str, now: i64) -> Result<CredentialReuseState, ModelError> {
    let (batch, unused, lifetime) = match method {
        Method::Unrestricted => (None, None, None),
        Method::OnceOnly => (Some(4), Some(1), None),
        Method::LimitedTime => (None, None, Some(5)),
        Method::RotatingBatch | Method::PerRelyingParty => (Some(4), None, Some(5)),
    };
    Ok(CredentialReuseState {
        id: NonEmptyIdentifier::new(id.into())?,
        policy: CredentialReusePolicySelection::new(
            NonEmptyIdentifier::new("pid".into())?,
            method,
            batch,
            unused,
            lifetime,
        )?,
        instances: (0..4)
            .map(|slot| {
                Ok(ReuseInstance {
                    credential_id: NonEmptyIdentifier::new(format!("{id}-credential-{slot}"))?,
                    valid_from: time(10)?,
                    valid_until: time(200)?,
                    retired: false,
                    uses: 0,
                    party_binding: None,
                })
            })
            .collect::<Result<Vec<_>, ModelError>>()?,
        next_index: 0,
        claims: vec![],
        replenishment: None,
        retired: false,
        updated_at: time(now)?,
    })
}

pub fn exercise(commands: &[[u8; 4]]) -> Result<(), ModelError> {
    for method in METHODS {
        exercise_policy(commands, method)?;
    }
    Ok(())
}

fn exercise_policy(commands: &[[u8; 4]], method: Method) -> Result<(), ModelError> {
    let mut state = cohort(method, "cohort", 10)?;
    for instance in &mut state.instances {
        instance.valid_until = time(EXPIRY)?;
    }
    let mut store = Store {
        state,
        replacement: None,
        revision: 1,
        rejection: None,
    };
    let mut model = Model {
        claims: BTreeMap::new(),
        uses: [0; 4],
        parties: [None; 4],
        next_slot: 0,
        updated: 10,
        retired: false,
        replenishment: None,
    };
    let id = store.state.id.clone();
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
        let before = store.state.clone();
        let revision = store.revision;
        match command[0] % 4 {
            0 | 1 => claim(&mut store, &mut model, method, command, now)?,
            2 => replenish(&mut store, &mut model, method, command[1], now)?,
            _ => {
                let operation = command[1];
                let expected =
                    if model.retired || now < model.updated || model.replenishment.is_none() {
                        Some(ReuseErrorReason::InvalidState)
                    } else if model.replenishment != Some(operation) {
                        Some(ReuseErrorReason::IntentConflict)
                    } else {
                        store.rejection.map(|_| ReuseErrorReason::Storage)
                    };
                let result = fulfill_replenishment(
                    &mut store,
                    &id,
                    [operation; 32],
                    cohort(method, "replacement", now)?,
                    time(now)?,
                );
                assert_eq!(result.err().map(|error| error.reason), expected);
                if expected.is_none() {
                    model.retired = true;
                    model.updated = now;
                }
            }
        }
        model.assert_state(&store);
        if store.revision == revision {
            assert!(store.state == before);
        }
    }
    Ok(())
}

fn claim(
    store: &mut Store,
    model: &mut Model,
    method: Method,
    command: &[u8; 4],
    now: i64,
) -> Result<(), ModelError> {
    let operation = command[1] % 16;
    let digest = command[2] % 8;
    let party = command[3] % 8;
    let slot = model.select(method, party);
    let expected = if operation == 0 || digest == 0 || party == 0 {
        Some(ReuseErrorReason::InvalidState)
    } else if let Some((prior_digest, prior_party, _)) = model.claims.get(&operation) {
        Some(if *prior_digest == digest && *prior_party == party {
            ReuseErrorReason::AlreadyCommitted
        } else {
            ReuseErrorReason::IntentConflict
        })
    } else if now < model.updated {
        Some(ReuseErrorReason::TimeRollback)
    } else if model.retired || now >= EXPIRY || slot.is_none() {
        Some(ReuseErrorReason::Exhausted)
    } else {
        store.rejection.map(|_| ReuseErrorReason::Storage)
    };
    let cohort_id = store.state.id.clone();
    let result = claim_credential_use(
        store,
        &cohort_id,
        [operation; 32],
        [digest; 32],
        [party; 32],
        time(now)?,
    );
    assert_eq!(result.as_ref().err().map(|error| error.reason), expected);
    if let Ok(credential) = result {
        let slot = slot.ok_or(ModelError::Arithmetic)?;
        assert_eq!(credential, store.state.instances[slot].credential_id);
        model.claims.insert(operation, (digest, party, slot));
        model.uses[slot] = model.uses[slot]
            .checked_add(1)
            .ok_or(ModelError::Arithmetic)?;
        if method == Method::PerRelyingParty {
            model.parties[slot] = Some(party);
        }
        if method == Method::RotatingBatch {
            model.next_slot = slot.checked_add(1).ok_or(ModelError::Arithmetic)? % 4;
        }
        model.updated = now;
    }
    Ok(())
}

fn replenish(
    store: &mut Store,
    model: &mut Model,
    method: Method,
    operation: u8,
    now: i64,
) -> Result<(), ModelError> {
    let expected = if operation == 0 {
        Some(ReuseErrorReason::InvalidState)
    } else if now < model.updated {
        Some(ReuseErrorReason::TimeRollback)
    } else if model.retired {
        Some(ReuseErrorReason::Exhausted)
    } else if let Some(prior) = model.replenishment {
        (prior != operation).then_some(ReuseErrorReason::IntentConflict)
    } else if model.decision(method, now) == ReplenishmentDecision::NotRequired {
        Some(ReuseErrorReason::InvalidState)
    } else {
        store.rejection.map(|_| ReuseErrorReason::Storage)
    };
    if now >= model.updated && !model.retired {
        assert_eq!(
            evaluate_replenishment(&store.state, time(now)?)?,
            model.decision(method, now)
        );
    }
    let cohort_id = store.state.id.clone();
    let result = request_replenishment(store, &cohort_id, [operation; 32], time(now)?);
    assert_eq!(result.err().map(|error| error.reason), expected);
    if expected.is_none() && model.replenishment.is_none() {
        model.replenishment = Some(operation);
        model.updated = now;
    }
    Ok(())
}
