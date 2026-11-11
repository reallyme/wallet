// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic reuse allocation, committed before any key or proof is exposed.

use reallyme_wallet_storage::{CredentialReuseStore, StorageError};
use reallyme_wallet_types::{
    CredentialRecordId, CredentialReuseMethod, CredentialReuseState, NonEmptyIdentifier,
    RecordRevision, ReplenishmentIntent, ReuseClaim, UnixTimestamp, MAX_REUSE_CLAIMS,
    MAX_REUSE_INSTANCES,
};
use std::collections::BTreeSet;
use thiserror::Error;

/// Fixed, privacy-safe reuse failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ReuseErrorReason {
    /// Persisted state or selected policy is inconsistent.
    #[error("invalid_state")]
    InvalidState,
    /// No usable instance remains for the selected policy.
    #[error("exhausted")]
    Exhausted,
    /// No new authorization may escape for a previously committed attempt.
    #[error("already_committed")]
    AlreadyCommitted,
    /// An operation identity was rebound to another intent or party.
    #[error("intent_conflict")]
    IntentConflict,
    /// Retained claims reached their explicit bound.
    #[error("claim_capacity")]
    ClaimCapacity,
    /// Clock rollback was observed.
    #[error("time_rollback")]
    TimeRollback,
    /// Provider operation failed with a stable storage reason.
    #[error("storage")]
    Storage,
}
/// Typed reuse error. Backend text and identifiers are never retained.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("reuse operation failed: {reason}")]
pub struct ReuseError {
    /// Domain reason.
    pub reason: ReuseErrorReason,
    /// Fixed storage reason when the provider failed.
    pub storage_reason: Option<reallyme_wallet_storage::StorageErrorReason>,
}
impl From<StorageError> for ReuseError {
    fn from(error: StorageError) -> Self {
        Self {
            reason: ReuseErrorReason::Storage,
            storage_reason: Some(error.reason),
        }
    }
}
pub(crate) fn error(reason: ReuseErrorReason) -> ReuseError {
    ReuseError {
        reason,
        storage_reason: None,
    }
}
/// Why a cohort should be replenished. Issuer calls require host authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplenishmentDecision {
    /// Every durable attempt slot is occupied; claims must never be evicted.
    ClaimCapacity,
    /// Every usable instance is already assigned to a relying party.
    PartyCapacity,
    /// No threshold has been reached.
    NotRequired,
    /// No currently usable instance remains.
    Exhausted,
    /// Remaining unallocated/unused instances reached the configured threshold.
    UnusedThreshold,
    /// Remaining authenticated lifetime reached the configured threshold.
    LifetimeThreshold,
}

/// Validate bounded persisted state before allocation, restore, or serialization.
pub fn validate_reuse_state(state: &CredentialReuseState) -> Result<(), ReuseError> {
    let count = state.instances.len();
    if state.id.as_str().is_empty()
        || state
            .policy
            .credential_configuration_id()
            .as_str()
            .is_empty()
        || count == 0
        || count > MAX_REUSE_INSTANCES
        || state.claims.len() > MAX_REUSE_CLAIMS
        || usize::try_from(state.next_index).map_or(true, |index| index >= count)
        || state
            .policy
            .batch_size()
            .is_some_and(|n| usize::try_from(n).ok() != Some(count))
    {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    let mut credentials = BTreeSet::new();
    let mut parties = BTreeSet::new();
    for instance in &state.instances {
        if instance.credential_id.as_str().is_empty()
            || instance.valid_until <= instance.valid_from
            || !credentials.insert(&instance.credential_id)
            || instance.party_binding.is_some_and(|party| party == [0; 32])
            || (state.policy.method() != CredentialReuseMethod::PerRelyingParty
                && instance.party_binding.is_some())
            || instance
                .party_binding
                .as_ref()
                .is_some_and(|party| !parties.insert(party))
        {
            return Err(error(ReuseErrorReason::InvalidState));
        }
        let claims: Vec<_> = state
            .claims
            .iter()
            .filter(|claim| claim.credential_id == instance.credential_id)
            .collect();
        if u64::try_from(claims.len()).ok() != Some(instance.uses)
            || (state.policy.method() == CredentialReuseMethod::OnceOnly && instance.uses > 1)
            || (state.policy.method() == CredentialReuseMethod::PerRelyingParty
                && (instance.party_binding.is_some() != (instance.uses > 0)
                    || claims
                        .iter()
                        .any(|claim| Some(claim.party_binding) != instance.party_binding)))
        {
            return Err(error(ReuseErrorReason::InvalidState));
        }
    }
    let mut operations = BTreeSet::new();
    let mut last_time = None;
    for claim in &state.claims {
        if claim.operation_id == [0; 32]
            || claim.request_digest == [0; 32]
            || claim.party_binding == [0; 32]
            || !operations.insert(&claim.operation_id)
            || !credentials.contains(&claim.credential_id)
            || claim.committed_at > state.updated_at
            || last_time.is_some_and(|time| claim.committed_at < time)
        {
            return Err(error(ReuseErrorReason::InvalidState));
        }
        last_time = Some(claim.committed_at);
    }
    if state.policy.method() != CredentialReuseMethod::RotatingBatch && state.next_index != 0 {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    if state.replenishment.as_ref().is_some_and(|intent| {
        intent.operation_id == [0; 32]
            || intent.requested_at > state.updated_at
            || (intent.fulfilled && !state.retired)
    }) {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    Ok(())
}

/// Create a fresh cohort only after its instances and policy crossed issuer validation.
pub fn create_reuse_cohort(
    store: &mut dyn CredentialReuseStore,
    state: CredentialReuseState,
) -> Result<RecordRevision, ReuseError> {
    validate_reuse_state(&state)?;
    if state.retired
        || state.replenishment.is_some()
        || !state.claims.is_empty()
        || state.next_index != 0
        || state
            .instances
            .iter()
            .any(|i| i.uses != 0 || i.retired || i.party_binding.is_some())
    {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    Ok(store.create_reuse_state(state)?)
}

/// Atomically reserve a use. Replays never return a fresh signing authorization.
pub fn claim_credential_use(
    store: &mut dyn CredentialReuseStore,
    cohort: &NonEmptyIdentifier,
    operation_id: [u8; 32],
    request_digest: [u8; 32],
    party_binding: [u8; 32],
    now: UnixTimestamp,
) -> Result<CredentialRecordId, ReuseError> {
    let (mut state, revision) = store.get_reuse_state(cohort)?.into_parts();
    validate_reuse_state(&state)?;
    if &state.id != cohort
        || operation_id == [0; 32]
        || request_digest == [0; 32]
        || party_binding == [0; 32]
    {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    if let Some(claim) = state
        .claims
        .iter()
        .find(|claim| claim.operation_id == operation_id)
    {
        return Err(error(
            if claim.request_digest == request_digest && claim.party_binding == party_binding {
                ReuseErrorReason::AlreadyCommitted
            } else {
                ReuseErrorReason::IntentConflict
            },
        ));
    }
    if now < state.updated_at {
        return Err(error(ReuseErrorReason::TimeRollback));
    }
    if state.retired {
        return Err(error(ReuseErrorReason::Exhausted));
    }
    if state.claims.len() == MAX_REUSE_CLAIMS {
        return Err(error(ReuseErrorReason::ClaimCapacity));
    }
    let method = state.policy.method();
    let usable = |index: usize| {
        state
            .instances
            .get(index)
            .is_some_and(|i| !i.retired && i.valid_from <= now && now < i.valid_until)
    };
    let selected = match method {
        CredentialReuseMethod::Unrestricted | CredentialReuseMethod::LimitedTime => {
            (0..state.instances.len()).find(|i| usable(*i))
        }
        CredentialReuseMethod::OnceOnly => {
            (0..state.instances.len()).find(|i| usable(*i) && state.instances[*i].uses == 0)
        }
        CredentialReuseMethod::PerRelyingParty => {
            match state
                .instances
                .iter()
                .position(|i| i.party_binding == Some(party_binding))
            {
                Some(index) => usable(index).then_some(index),
                None => (0..state.instances.len())
                    .find(|i| usable(*i) && state.instances[*i].party_binding.is_none()),
            }
        }
        CredentialReuseMethod::RotatingBatch => {
            let start = usize::try_from(state.next_index)
                .map_err(|_| error(ReuseErrorReason::InvalidState))?;
            let mut found = None;
            for offset in 0..state.instances.len() {
                let index = start
                    .checked_add(offset)
                    .ok_or_else(|| error(ReuseErrorReason::InvalidState))?
                    % state.instances.len();
                if usable(index) {
                    found = Some(index);
                    break;
                }
            }
            found
        }
    }
    .ok_or_else(|| error(ReuseErrorReason::Exhausted))?;
    let instance = state
        .instances
        .get_mut(selected)
        .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
    instance.uses = instance
        .uses
        .checked_add(1)
        .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
    if method == CredentialReuseMethod::PerRelyingParty {
        instance.party_binding = Some(party_binding);
    }
    let credential_id = instance.credential_id.clone();
    state.claims.push(ReuseClaim {
        operation_id,
        request_digest,
        party_binding,
        credential_id: credential_id.clone(),
        committed_at: now,
    });
    if method == CredentialReuseMethod::RotatingBatch {
        let next = selected
            .checked_add(1)
            .ok_or_else(|| error(ReuseErrorReason::InvalidState))?
            % state.instances.len();
        state.next_index =
            u32::try_from(next).map_err(|_| error(ReuseErrorReason::InvalidState))?;
    }
    state.updated_at = now;
    validate_reuse_state(&state)?;
    let committed = store.compare_and_swap_reuse_state(revision, state)?;
    if committed <= revision {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    Ok(credential_id)
}

/// Evaluate replenishment from authenticated validity windows and explicit time.
pub fn evaluate_replenishment(
    state: &CredentialReuseState,
    now: UnixTimestamp,
) -> Result<ReplenishmentDecision, ReuseError> {
    validate_reuse_state(state)?;
    if now < state.updated_at {
        return Err(error(ReuseErrorReason::TimeRollback));
    }
    if state.retired {
        return Err(error(ReuseErrorReason::Exhausted));
    }
    if state.claims.len() == MAX_REUSE_CLAIMS {
        return Ok(ReplenishmentDecision::ClaimCapacity);
    }
    let mut unassigned = 0_u32;
    let mut usable = 0_u32;
    let mut unused = 0_u32;
    let mut minimum_lifetime = None;
    for instance in &state.instances {
        if instance.retired || now < instance.valid_from || now >= instance.valid_until {
            continue;
        }
        if state.policy.method() == CredentialReuseMethod::OnceOnly && instance.uses > 0 {
            continue;
        }
        usable = usable
            .checked_add(1)
            .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
        if instance.party_binding.is_none() {
            unassigned = unassigned
                .checked_add(1)
                .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
        }
        if instance.uses == 0 {
            unused = unused
                .checked_add(1)
                .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
        }
        let left = instance
            .valid_until
            .as_seconds()
            .checked_sub(now.as_seconds())
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
        minimum_lifetime =
            Some(minimum_lifetime.map_or(left, |current| core::cmp::min(left, current)));
    }
    Ok(if usable == 0 {
        ReplenishmentDecision::Exhausted
    } else if state.policy.method() == CredentialReuseMethod::PerRelyingParty && unassigned == 0 {
        ReplenishmentDecision::PartyCapacity
    } else if state
        .policy
        .reissue_trigger_unused()
        .is_some_and(|threshold| unused <= threshold)
    {
        ReplenishmentDecision::UnusedThreshold
    } else if state
        .policy
        .reissue_trigger_lifetime_left_seconds()
        .is_some_and(|threshold| minimum_lifetime.is_some_and(|left| left <= threshold))
    {
        ReplenishmentDecision::LifetimeThreshold
    } else {
        ReplenishmentDecision::NotRequired
    })
}

/// Persist a stable replenishment intent with the observed threshold state.
pub fn request_replenishment(
    store: &mut dyn CredentialReuseStore,
    cohort: &NonEmptyIdentifier,
    operation_id: [u8; 32],
    now: UnixTimestamp,
) -> Result<RecordRevision, ReuseError> {
    let (mut state, revision) = store.get_reuse_state(cohort)?.into_parts();
    if &state.id != cohort || operation_id == [0; 32] {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    let decision = evaluate_replenishment(&state, now)?;
    if let Some(existing) = &state.replenishment {
        return if existing.operation_id == operation_id {
            Ok(revision)
        } else {
            Err(error(ReuseErrorReason::IntentConflict))
        };
    }
    if decision == ReplenishmentDecision::NotRequired {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    state.replenishment = Some(ReplenishmentIntent {
        operation_id,
        requested_at: now,
        fulfilled: false,
    });
    state.updated_at = now;
    let committed = store.compare_and_swap_reuse_state(revision, state)?;
    if committed <= revision {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    Ok(committed)
}

/// Fulfill replenishment only with a fresh validated replacement cohort. Retire
/// the old cohort atomically; its attempt and party history is never reset.
pub fn fulfill_replenishment(
    store: &mut dyn CredentialReuseStore,
    cohort: &NonEmptyIdentifier,
    operation_id: [u8; 32],
    replacement: CredentialReuseState,
    now: UnixTimestamp,
) -> Result<RecordRevision, ReuseError> {
    let (mut state, revision) = store.get_reuse_state(cohort)?.into_parts();
    validate_reuse_state(&state)?;
    validate_reuse_state(&replacement)?;
    if &state.id != cohort
        || state.retired
        || now < state.updated_at
        || replacement.updated_at != now
        || replacement.id == state.id
        || replacement.policy != state.policy
        || replacement.retired
        || !replacement.claims.is_empty()
        || replacement.replenishment.is_some()
        || replacement.next_index != 0
        || replacement.instances.iter().any(|i| {
            i.retired
                || i.uses != 0
                || i.party_binding.is_some()
                || i.valid_from > now
                || i.valid_until <= now
                || state
                    .instances
                    .iter()
                    .any(|old| old.credential_id == i.credential_id)
        })
    {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    let intent = state
        .replenishment
        .as_mut()
        .ok_or_else(|| error(ReuseErrorReason::InvalidState))?;
    if intent.operation_id != operation_id || intent.fulfilled {
        return Err(error(ReuseErrorReason::IntentConflict));
    }
    intent.fulfilled = true;
    state.retired = true;
    state.updated_at = now;
    let committed = store.commit_replenishment(revision, state, replacement)?;
    if committed <= revision {
        return Err(error(ReuseErrorReason::InvalidState));
    }
    Ok(committed)
}

#[cfg(test)]
#[path = "enforce_reuse_tests.rs"]
mod tests;
