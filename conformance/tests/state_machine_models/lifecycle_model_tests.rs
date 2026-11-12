// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A policy edge table and independent resume/failure state challenge transitions.

use super::{time, ModelError};
use reallyme_wallet::lifecycle::{
    apply_reconciled_wallet_lifecycle_retry, apply_wallet_lifecycle_event,
    ensure_wallet_operation_allowed, new_wallet_lifecycle, restore_wallet_lifecycle,
    LifecycleErrorReason, ReconciledWalletLifecycleRetry, WalletLifecycleEvent as Event,
    WalletLifecycleEvidenceKind as Evidence, WalletLifecycleEvidenceRecord,
    WalletLifecycleState as State, WalletOperation,
};
use reallyme_wallet::types::NonEmptyIdentifier;

const EVENTS: [Event; 14] = [
    Event::BeginProvisioning,
    Event::CompleteProvisioning,
    Event::Suspend,
    Event::Reactivate,
    Event::BeginRecovery,
    Event::CompleteRecovery,
    Event::BeginMigration,
    Event::CompleteMigration,
    Event::BeginWithdrawal,
    Event::CompleteWithdrawal,
    Event::BeginDeletion,
    Event::CompleteDeletion,
    Event::MarkFailed,
    Event::RetryProvisioning,
];

// Ordinary policy edges are data, rather than calling the implementation's
// transition classifier to decide what the test should expect.
const EDGES: [(State, Event, State); 11] = [
    (
        State::Unprovisioned,
        Event::BeginProvisioning,
        State::Provisioning,
    ),
    (
        State::Provisioning,
        Event::CompleteProvisioning,
        State::Active,
    ),
    (State::Active, Event::Suspend, State::Suspended),
    (State::Suspended, Event::Reactivate, State::Active),
    (State::Active, Event::BeginRecovery, State::RecoveryPending),
    (
        State::Suspended,
        Event::BeginRecovery,
        State::RecoveryPending,
    ),
    (
        State::Active,
        Event::BeginMigration,
        State::MigrationPending,
    ),
    (
        State::Suspended,
        Event::BeginMigration,
        State::MigrationPending,
    ),
    (
        State::WithdrawalPending,
        Event::CompleteWithdrawal,
        State::Withdrawn,
    ),
    (
        State::DeletionPending,
        Event::CompleteDeletion,
        State::Deleted,
    ),
    (State::Failed, Event::RetryProvisioning, State::Provisioning),
];

struct Model {
    state: State,
    resume: Option<State>,
    failed_from: Option<State>,
    updated: i64,
}

impl Model {
    fn retry(&self, event: Event) -> bool {
        self.state == State::Failed
            && matches!(
                (self.failed_from, event),
                (Some(State::RecoveryPending), Event::BeginRecovery)
                    | (Some(State::MigrationPending), Event::BeginMigration)
            )
    }
    fn next(&self, event: Event, reconciled: bool) -> Option<State> {
        match event {
            Event::BeginDeletion => {
                (!matches!(self.state, State::Deleted | State::DeletionPending))
                    .then_some(State::DeletionPending)
            }
            Event::MarkFailed => matches!(
                self.state,
                State::Provisioning
                    | State::RecoveryPending
                    | State::MigrationPending
                    | State::WithdrawalPending
                    | State::DeletionPending
            )
            .then_some(State::Failed),
            Event::CompleteRecovery if self.state == State::RecoveryPending => self.resume,
            Event::CompleteMigration if self.state == State::MigrationPending => self.resume,
            Event::BeginRecovery | Event::BeginMigration if self.retry(event) => reconciled
                .then_some(if event == Event::BeginRecovery {
                    State::RecoveryPending
                } else {
                    State::MigrationPending
                }),
            Event::BeginWithdrawal => {
                let pending = matches!(
                    self.state,
                    State::Active
                        | State::Suspended
                        | State::RecoveryPending
                        | State::MigrationPending
                );
                let failed = self.state == State::Failed
                    && matches!(
                        self.failed_from,
                        Some(
                            State::RecoveryPending
                                | State::MigrationPending
                                | State::WithdrawalPending
                        )
                    );
                (pending || failed).then_some(State::WithdrawalPending)
            }
            Event::RetryProvisioning if self.failed_from != Some(State::Provisioning) => None,
            _ => EDGES.iter().find_map(|(state, candidate, next)| {
                (*state == self.state && *candidate == event).then_some(*next)
            }),
        }
    }
    fn advance(&mut self, event: Event, next: State, now: i64) {
        if matches!(event, Event::BeginRecovery | Event::BeginMigration)
            && matches!(self.state, State::Active | State::Suspended)
        {
            self.resume = Some(self.state);
        } else if !matches!(
            event,
            Event::MarkFailed | Event::BeginRecovery | Event::BeginMigration
        ) {
            self.resume = None;
        }
        self.failed_from = (event == Event::MarkFailed).then_some(self.state);
        self.state = next;
        self.updated = now;
    }
}

fn evidence_kind(event: Event, state: State) -> Evidence {
    match event {
        Event::BeginRecovery | Event::CompleteRecovery => Evidence::Recovery,
        Event::BeginMigration | Event::CompleteMigration => Evidence::Migration,
        Event::BeginWithdrawal | Event::CompleteWithdrawal => Evidence::Withdrawal,
        Event::BeginDeletion | Event::CompleteDeletion => Evidence::Deletion,
        Event::Suspend => Evidence::Suspension,
        Event::Reactivate => Evidence::Reactivation,
        Event::MarkFailed => match state {
            State::RecoveryPending => Evidence::Recovery,
            State::MigrationPending => Evidence::Migration,
            State::WithdrawalPending => Evidence::Withdrawal,
            State::DeletionPending => Evidence::Deletion,
            _ => Evidence::Provisioning,
        },
        _ => Evidence::Provisioning,
    }
}

pub fn exercise(commands: &[[u8; 4]]) -> Result<(), ModelError> {
    let wallet = NonEmptyIdentifier::new("model-wallet".into())?;
    let mut actual = new_wallet_lifecycle(wallet.clone(), time(10)?);
    let mut model = Model {
        state: State::Unprovisioned,
        resume: None,
        failed_from: None,
        updated: 10,
    };
    for (index, command) in commands.iter().enumerate() {
        let event = EVENTS[usize::from(command[0] % 14)];
        let now = if command[3] & 16 != 0 {
            model.updated.checked_sub(1)
        } else {
            i64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(10))
        }
        .ok_or(ModelError::Arithmetic)?;
        let wrong_wallet = command[3] & 2 != 0;
        let missing = command[3] & 4 != 0;
        let reconciled = model.retry(event) && command[3] & 8 != 0 && !missing;
        let evidence = WalletLifecycleEvidenceRecord {
            id: NonEmptyIdentifier::new(format!("model-evidence-{index}"))?,
            wallet_instance_id: if wrong_wallet {
                NonEmptyIdentifier::new("other-wallet".into())?
            } else {
                wallet.clone()
            },
            kind: evidence_kind(event, model.state),
            event,
            occurred_at: time(now)?,
            authority_id: NonEmptyIdentifier::new("test-authority".into())?,
            evidence_ref: NonEmptyIdentifier::new("test-reference".into())?,
            evidence_digest: vec![1; 32],
        };
        let next = model.next(event, reconciled);
        let expected = if reconciled && (now < model.updated || wrong_wallet) {
            Some(LifecycleErrorReason::InvalidEvidence)
        } else if now < model.updated {
            Some(LifecycleErrorReason::ClockRollback)
        } else if wrong_wallet || missing {
            Some(LifecycleErrorReason::InvalidEvidence)
        } else if next.is_none() {
            Some(LifecycleErrorReason::InvalidTransition)
        } else {
            None
        };
        let result = if reconciled {
            ReconciledWalletLifecycleRetry::new(actual.clone(), evidence.clone(), time(now)?)
                .and_then(|receipt| {
                    apply_reconciled_wallet_lifecycle_retry(
                        actual.clone(),
                        &evidence,
                        receipt,
                        evidence.occurred_at,
                    )
                })
        } else {
            apply_wallet_lifecycle_event(
                actual.clone(),
                event,
                time(now)?,
                (!missing).then_some(&evidence),
            )
        };
        assert_eq!(result.as_ref().err().map(|error| error.reason), expected);
        if let Ok(record) = result {
            model.advance(event, next.ok_or(ModelError::Arithmetic)?, now);
            actual = record;
        }
        assert_eq!(actual.state(), model.state);
        assert_eq!(actual.resume_state(), model.resume);
        assert_eq!(actual.failed_from(), model.failed_from);
        assert_eq!(actual.updated_at().as_seconds(), model.updated);
        assert_eq!(
            ensure_wallet_operation_allowed(&actual, WalletOperation::PresentCredential).is_ok(),
            model.state == State::Active
        );
        let restored = restore_wallet_lifecycle(
            wallet.clone(),
            actual.state(),
            actual.updated_at(),
            actual.last_event(),
            actual.resume_state(),
            actual.failed_from(),
            actual.last_evidence().cloned(),
        )?;
        assert_eq!(restored, actual);
    }
    Ok(())
}
