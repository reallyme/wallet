// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    claim_credential_use, create_reuse_cohort, evaluate_replenishment, request_replenishment,
    validate_reuse_state, ReplenishmentDecision, ReuseError, ReuseErrorReason,
};
use reallyme_wallet_storage::{
    CredentialReuseStore, StorageError, StorageErrorReason, StorageResult,
};
use reallyme_wallet_types::{
    CredentialRecordId, CredentialReuseMethod, CredentialReusePolicySelection,
    CredentialReuseState, NonEmptyIdentifier, RecordRevision, ReuseInstance, UnixTimestamp,
    Versioned, WalletTypesError,
};
use thiserror::Error;

#[derive(Default)]
struct Store {
    replacement: Option<CredentialReuseState>,
    state: Option<CredentialReuseState>,
    generation: u64,
    fail: bool,
}
impl CredentialReuseStore for Store {
    fn create_reuse_state(&mut self, state: CredentialReuseState) -> StorageResult<RecordRevision> {
        if self.state.is_some() {
            return Err(StorageError::new(StorageErrorReason::RecordAlreadyExists));
        }
        self.state = Some(state);
        self.generation = 1;
        Ok(RecordRevision::new(1))
    }
    fn commit_replenishment(
        &mut self,
        expected: RecordRevision,
        retired: CredentialReuseState,
        replacement: CredentialReuseState,
    ) -> StorageResult<RecordRevision> {
        if self.fail {
            return Err(StorageError::new(StorageErrorReason::WriteRejected));
        }
        let revision = self.compare_and_swap_reuse_state(expected, retired)?;
        self.replacement = Some(replacement);
        Ok(revision)
    }
    fn get_reuse_state(
        &self,
        _: &NonEmptyIdentifier,
    ) -> StorageResult<Versioned<CredentialReuseState>> {
        Ok(Versioned::new(
            self.state
                .clone()
                .ok_or(StorageError::new(StorageErrorReason::RecordNotFound))?,
            RecordRevision::new(self.generation),
        ))
    }
    fn compare_and_swap_reuse_state(
        &mut self,
        expected: RecordRevision,
        state: CredentialReuseState,
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
        self.state = Some(state);
        Ok(RecordRevision::new(self.generation))
    }
}
fn time(n: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(n)
}
fn state(method: CredentialReuseMethod) -> Result<CredentialReuseState, WalletTypesError> {
    let (size, unused, lifetime) = match method {
        CredentialReuseMethod::Unrestricted => (None, None, None),
        CredentialReuseMethod::OnceOnly => (Some(2), Some(1), None),
        CredentialReuseMethod::LimitedTime => (None, None, Some(10)),
        CredentialReuseMethod::RotatingBatch | CredentialReuseMethod::PerRelyingParty => {
            (Some(2), None, Some(10))
        }
    };
    Ok(CredentialReuseState {
        id: NonEmptyIdentifier::new("cohort".into())?,
        policy: CredentialReusePolicySelection::new(
            NonEmptyIdentifier::new("pid".into())?,
            method,
            size,
            unused,
            lifetime,
        )?,
        instances: vec![
            ReuseInstance {
                credential_id: CredentialRecordId::new("a".into())?,
                valid_from: time(10)?,
                valid_until: time(100)?,
                retired: false,
                uses: 0,
                party_binding: None,
            },
            ReuseInstance {
                credential_id: CredentialRecordId::new("b".into())?,
                valid_from: time(10)?,
                valid_until: time(100)?,
                retired: false,
                uses: 0,
                party_binding: None,
            },
        ],
        next_index: 0,
        claims: vec![],
        replenishment: None,
        retired: false,
        updated_at: time(10)?,
    })
}
fn claim(store: &mut Store, id: u8, party: u8) -> Result<CredentialRecordId, TestError> {
    Ok(claim_credential_use(
        store,
        &NonEmptyIdentifier::new("cohort".into())?,
        [id; 32],
        [3; 32],
        [party; 32],
        time(20)?,
    )?)
}
#[test]
fn once_only_survives_restart_and_retry() -> Result<(), TestError> {
    let mut store = Store::default();
    create_reuse_cohort(&mut store, state(CredentialReuseMethod::OnceOnly)?)?;
    assert_eq!(claim(&mut store, 1, 5)?.as_str(), "a");
    let mut restarted = Store {
        state: store.state.clone(),
        generation: store.generation,
        fail: false,
        replacement: None,
    };
    assert!(
        matches!(claim(&mut restarted,1,5),Err(TestError::Reuse(e)) if e.reason==ReuseErrorReason::AlreadyCommitted)
    );
    assert_eq!(claim(&mut restarted, 2, 5)?.as_str(), "b");
    assert!(
        matches!(claim(&mut restarted,3,5),Err(TestError::Reuse(e)) if e.reason==ReuseErrorReason::Exhausted)
    );
    Ok(())
}
#[test]
fn rotating_batch_and_per_party_have_distinct_allocation() -> Result<(), TestError> {
    for method in [
        CredentialReuseMethod::RotatingBatch,
        CredentialReuseMethod::PerRelyingParty,
    ] {
        let mut store = Store::default();
        create_reuse_cohort(&mut store, state(method)?)?;
        assert_eq!(claim(&mut store, 1, 5)?.as_str(), "a");
        assert_eq!(
            claim(&mut store, 2, 5)?.as_str(),
            if method == CredentialReuseMethod::RotatingBatch {
                "b"
            } else {
                "a"
            }
        );
        if method == CredentialReuseMethod::PerRelyingParty {
            assert_eq!(claim(&mut store, 3, 6)?.as_str(), "b");
            assert!(
                matches!(claim(&mut store,4,7),Err(TestError::Reuse(e)) if e.reason==ReuseErrorReason::Exhausted)
            );
        } else {
            assert_eq!(claim(&mut store, 3, 5)?.as_str(), "a");
        }
    }
    Ok(())
}
#[test]
fn failed_commit_exposes_no_selection_and_stale_writers_lose() -> Result<(), TestError> {
    let mut store = Store::default();
    let initial = state(CredentialReuseMethod::OnceOnly)?;
    create_reuse_cohort(&mut store, initial.clone())?;
    store.fail = true;
    assert!(claim(&mut store, 1, 5).is_err());
    assert!(store.state.as_ref().is_some_and(|s| s.claims.is_empty()));
    store.fail = false;
    claim(&mut store, 1, 5)?;
    assert!(
        matches!(store.compare_and_swap_reuse_state(RecordRevision::new(1),initial),Err(e) if e.reason==StorageErrorReason::RevisionConflict)
    );
    Ok(())
}
#[test]
fn thresholds_are_inclusive_and_intent_is_stable() -> Result<(), TestError> {
    let mut store = Store::default();
    create_reuse_cohort(&mut store, state(CredentialReuseMethod::OnceOnly)?)?;
    claim(&mut store, 1, 5)?;
    let (s, _) = store
        .get_reuse_state(&NonEmptyIdentifier::new("cohort".into())?)?
        .into_parts();
    assert_eq!(
        evaluate_replenishment(&s, time(20)?)?,
        ReplenishmentDecision::UnusedThreshold
    );
    let revision = request_replenishment(&mut store, &s.id, [9; 32], time(20)?)?;
    assert!(request_replenishment(&mut store, &s.id, [9; 32], time(21)?)? == revision);
    assert!(request_replenishment(&mut store, &s.id, [8; 32], time(21)?).is_err());
    let s = state(CredentialReuseMethod::LimitedTime)?;
    assert_eq!(
        evaluate_replenishment(&s, time(89)?)?,
        ReplenishmentDecision::NotRequired
    );
    assert_eq!(
        evaluate_replenishment(&s, time(90)?)?,
        ReplenishmentDecision::LifetimeThreshold
    );
    assert_eq!(
        evaluate_replenishment(&s, time(100)?)?,
        ReplenishmentDecision::Exhausted
    );
    Ok(())
}
#[test]
fn rejects_invalid_bounds_time_and_rebound_intent() -> Result<(), TestError> {
    let mut invalid = state(CredentialReuseMethod::OnceOnly)?;
    invalid.instances.clear();
    assert!(validate_reuse_state(&invalid).is_err());
    let mut invalid = state(CredentialReuseMethod::OnceOnly)?;
    invalid.next_index = u32::MAX;
    assert!(validate_reuse_state(&invalid).is_err());
    let mut invalid = state(CredentialReuseMethod::OnceOnly)?;
    invalid.instances[0].valid_until = time(10)?;
    assert!(validate_reuse_state(&invalid).is_err());
    let mut store = Store::default();
    create_reuse_cohort(&mut store, state(CredentialReuseMethod::OnceOnly)?)?;
    claim(&mut store, 1, 5)?;
    assert!(
        matches!(claim(&mut store,1,6),Err(TestError::Reuse(e)) if e.reason==ReuseErrorReason::IntentConflict)
    );
    let id = NonEmptyIdentifier::new("cohort".into())?;
    assert_eq!(
        claim_credential_use(&mut store, &id, [2; 32], [3; 32], [5; 32], time(19)?)
            .err()
            .map(|e| e.reason),
        Some(ReuseErrorReason::TimeRollback)
    );
    assert_eq!(
        claim_credential_use(&mut store, &id, [2; 32], [3; 32], [5; 32], time(100)?)
            .err()
            .map(|e| e.reason),
        Some(ReuseErrorReason::Exhausted)
    );
    Ok(())
}
#[test]
fn replenishment_commits_retirement_and_replacement_together() -> Result<(), TestError> {
    let mut store = Store::default();
    create_reuse_cohort(&mut store, state(CredentialReuseMethod::OnceOnly)?)?;
    claim(&mut store, 1, 5)?;
    let cohort = NonEmptyIdentifier::new("cohort".into())?;
    request_replenishment(&mut store, &cohort, [9; 32], time(20)?)?;
    let mut replacement = state(CredentialReuseMethod::OnceOnly)?;
    replacement.id = NonEmptyIdentifier::new("replacement".into())?;
    replacement.updated_at = time(21)?;
    replacement.instances[0].credential_id = CredentialRecordId::new("c".into())?;
    replacement.instances[1].credential_id = CredentialRecordId::new("d".into())?;
    store.fail = true;
    assert!(super::fulfill_replenishment(
        &mut store,
        &cohort,
        [9; 32],
        replacement.clone(),
        time(21)?
    )
    .is_err());
    assert!(store.replacement.is_none());
    assert!(store.state.as_ref().is_some_and(|s| !s.retired));
    store.fail = false;
    super::fulfill_replenishment(&mut store, &cohort, [9; 32], replacement, time(21)?)?;
    assert!(store.replacement.is_some());
    assert!(store
        .state
        .as_ref()
        .is_some_and(|s| s.retired && s.claims.len() == 1));
    assert!(claim(&mut store, 2, 5).is_err());
    Ok(())
}

#[derive(Debug, Error)]
enum TestError {
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("reuse")]
    Reuse(#[from] ReuseError),
    #[error("storage")]
    Storage(#[from] StorageError),
    #[error("missing_state")]
    MissingState,
}

#[test]
fn bounded_attempt_history_and_party_exhaustion_trigger_replenishment() -> Result<(), TestError> {
    let mut store = Store::default();
    create_reuse_cohort(&mut store, state(CredentialReuseMethod::RotatingBatch)?)?;
    let cohort = NonEmptyIdentifier::new("cohort".into())?;
    for number in 1_u32..=512 {
        let mut operation = [0_u8; 32];
        operation[28..32].copy_from_slice(&number.to_be_bytes());
        claim_credential_use(&mut store, &cohort, operation, [3; 32], [5; 32], time(20)?)?;
    }
    let (current, _) = store.get_reuse_state(&cohort)?.into_parts();
    assert_eq!(
        current.claims.len(),
        reallyme_wallet_types::MAX_REUSE_CLAIMS
    );
    assert_eq!(
        evaluate_replenishment(&current, time(20)?)?,
        ReplenishmentDecision::ClaimCapacity
    );
    assert_eq!(
        claim_credential_use(&mut store, &cohort, [9; 32], [3; 32], [5; 32], time(20)?)
            .err()
            .map(|e| e.reason),
        Some(ReuseErrorReason::ClaimCapacity)
    );
    request_replenishment(&mut store, &cohort, [8; 32], time(20)?)?;
    let mut parties = Store::default();
    create_reuse_cohort(&mut parties, state(CredentialReuseMethod::PerRelyingParty)?)?;
    claim(&mut parties, 1, 5)?;
    claim(&mut parties, 2, 6)?;
    let (current, _) = parties.get_reuse_state(&cohort)?.into_parts();
    assert_eq!(
        evaluate_replenishment(&current, time(20)?)?,
        ReplenishmentDecision::PartyCapacity
    );
    Ok(())
}

fn inventory_record(
    credential_id: &str,
    status: reallyme_wallet_types::CredentialStatus,
) -> Result<reallyme_wallet_types::CredentialRecord, WalletTypesError> {
    Ok(reallyme_wallet_types::CredentialRecord::new(
        CredentialRecordId::new(credential_id.into())?,
        NonEmptyIdentifier::new("issuer-1".into())?,
        None,
        None,
        None,
        reallyme_wallet_types::CredentialFormat::SdJwtVc,
        status,
        time(10)?,
        reallyme_wallet_types::EncryptedRecord {
            header: reallyme_wallet_types::EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".into())?,
                algorithm: reallyme_wallet_types::StorageEncryptionAlgorithm::Aes256GcmSiv,
                created_at: time(10)?,
            },
            nonce: vec![1; 12],
            aad: vec![2],
            ciphertext: vec![3; 16],
        },
    ))
}

#[test]
fn revoked_credentials_stop_counting_as_usable_after_retirement() -> Result<(), TestError> {
    use reallyme_wallet_types::CredentialStatus;
    let mut store = Store::default();
    create_reuse_cohort(&mut store, state(CredentialReuseMethod::OnceOnly)?)?;
    let cohort = NonEmptyIdentifier::new("cohort".into())?;

    // Active and suspended credentials keep their instance: a suspension can
    // still be lifted.
    for status in [CredentialStatus::Active, CredentialStatus::Suspended] {
        assert!(matches!(
            crate::retire_reuse_instance(
                &mut store,
                &cohort,
                &inventory_record("a", status)?,
                time(20)?,
            ),
            Err(error) if error.reason == ReuseErrorReason::InvalidState
        ));
    }
    for id in ["a", "b"] {
        crate::retire_reuse_instance(
            &mut store,
            &cohort,
            &inventory_record(id, CredentialStatus::Revoked)?,
            time(20)?,
        )?;
    }
    let state = store.state.clone().ok_or(TestError::MissingState)?;
    assert!(state.instances.iter().all(|instance| instance.retired));
    assert_eq!(
        evaluate_replenishment(&state, time(20)?)?,
        ReplenishmentDecision::Exhausted
    );
    Ok(())
}
