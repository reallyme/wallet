// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory runtime backend shared by the native HTTP adapter tests.

use std::collections::BTreeMap;
use std::time::Duration;

use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_runtime::{
    FlowSnapshotWriteResult, OperationIdempotencyKey, OperationReplayDecision,
    OperationRequestDigest, OperationReservation, RecordRevision, RuntimeError, RuntimeErrorReason,
    VersionedCredentialRecord, VersionedFlowSnapshot, VersionedWalletLifecycleRecord,
    WalletRuntimeBackend,
};
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

pub(crate) enum JournalEntry {
    InProgress {
        request_digest: [u8; 32],
        reservation: u64,
    },
    Complete {
        request_digest: [u8; 32],
        response: Vec<u8>,
    },
}

#[derive(Default)]
pub(crate) struct MemoryBackend {
    pub(crate) credentials: BTreeMap<String, wallet::CredentialRecord>,
    pub(crate) credential_revisions: BTreeMap<String, RecordRevision>,
    pub(crate) snapshots: BTreeMap<String, wallet::FlowSnapshot>,
    pub(crate) snapshot_revisions: BTreeMap<String, RecordRevision>,
    pub(crate) lifecycles: BTreeMap<String, lifecycle::WalletLifecycleRecord>,
    pub(crate) lifecycle_revisions: BTreeMap<String, RecordRevision>,
    pub(crate) journal: BTreeMap<[u8; 32], JournalEntry>,
    pub(crate) reservation_keys: BTreeMap<u64, [u8; 32]>,
    pub(crate) next_reservation: u64,
    pub(crate) commit_delay: Duration,
    pub(crate) panic_on_begin: bool,
}

impl WalletRuntimeBackend for MemoryBackend {
    fn authorize_wallet_operation(
        &mut self,
        _operation: reallyme_wallet_lifecycle::WalletOperation,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            RuntimeErrorReason::LifecycleStoreRejected,
        ))
    }

    fn bound_wallet_instance_id(&self) -> Option<wallet::NonEmptyIdentifier> {
        wallet::NonEmptyIdentifier::new("wallet-unit-1".to_owned()).ok()
    }

    fn trusted_now(&mut self) -> Result<wallet::UnixTimestamp, RuntimeError> {
        wallet::UnixTimestamp::from_seconds(11)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::TrustedClockUnavailable))
    }

    fn verify_wallet_lifecycle_authority(
        &mut self,
        _current: &reallyme_wallet_lifecycle::WalletLifecycleRecord,
        _event: reallyme_wallet_lifecycle::WalletLifecycleEvent,
        _evidence: &reallyme_wallet_lifecycle::WalletLifecycleEvidenceRecord,
        _now: wallet::UnixTimestamp,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied))
    }

    #[allow(clippy::panic)]
    fn begin_idempotent_operation(
        &mut self,
        key: &OperationIdempotencyKey,
        request_digest: &OperationRequestDigest,
    ) -> Result<OperationReplayDecision, RuntimeError> {
        // Simulates an injected backend that panics while holding the runtime.
        if self.panic_on_begin {
            panic!("injected backend failure");
        }
        let key_bytes = *key.as_bytes();
        let digest_bytes = *request_digest.as_bytes();
        match self.journal.get(&key_bytes) {
            Some(JournalEntry::InProgress { request_digest, .. })
                if request_digest == &digest_bytes =>
            {
                Err(RuntimeError::new(RuntimeErrorReason::OperationInProgress))
            }
            Some(JournalEntry::Complete {
                request_digest,
                response,
            }) if request_digest == &digest_bytes => Ok(OperationReplayDecision::Replay(
                Zeroizing::new(response.clone()),
            )),
            Some(_) => Err(RuntimeError::new(RuntimeErrorReason::IdempotencyConflict)),
            None => {
                self.next_reservation =
                    self.next_reservation
                        .checked_add(1)
                        .ok_or(RuntimeError::new(
                            RuntimeErrorReason::IdempotencyStoreRejected,
                        ))?;
                let reservation = self.next_reservation;
                self.journal.insert(
                    key_bytes,
                    JournalEntry::InProgress {
                        request_digest: digest_bytes,
                        reservation,
                    },
                );
                self.reservation_keys.insert(reservation, key_bytes);
                OperationReservation::from_provider_value(reservation)
                    .map(OperationReplayDecision::Execute)
                    .map_err(|_| RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected))
            }
        }
    }

    fn commit_idempotent_operation(
        &mut self,
        reservation: &OperationReservation,
        response: &[u8],
    ) -> Result<(), RuntimeError> {
        let reservation_value = reservation.value();
        let key = self
            .reservation_keys
            .remove(&reservation_value)
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            ))?;
        let request_digest = match self.journal.get(&key) {
            Some(JournalEntry::InProgress {
                request_digest,
                reservation,
            }) if *reservation == reservation_value => *request_digest,
            _ => {
                return Err(RuntimeError::new(
                    RuntimeErrorReason::IdempotencyStoreRejected,
                ))
            }
        };
        self.journal.insert(
            key,
            JournalEntry::Complete {
                request_digest,
                response: response.to_vec(),
            },
        );
        if !self.commit_delay.is_zero() {
            std::thread::sleep(self.commit_delay);
        }
        Ok(())
    }

    fn create_credential_record(
        &mut self,
        record: wallet::CredentialRecord,
    ) -> Result<wallet::CredentialRecordId, RuntimeError> {
        let id = record.id.clone();
        if self.credentials.contains_key(id.as_str()) {
            return Err(RuntimeError::new(
                RuntimeErrorReason::CredentialAlreadyExists,
            ));
        }
        let revision = RecordRevision::new(1);
        self.credentials.insert(id.as_str().to_owned(), record);
        self.credential_revisions
            .insert(id.as_str().to_owned(), revision);
        Ok(id)
    }

    fn get_credential_record(
        &mut self,
        id: &wallet::CredentialRecordId,
    ) -> Result<VersionedCredentialRecord, RuntimeError> {
        let record = self
            .credentials
            .get(id.as_str())
            .cloned()
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::CredentialStoreRejected,
            ))?;
        let revision =
            self.credential_revisions
                .get(id.as_str())
                .copied()
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::CredentialStoreRejected,
                ))?;
        Ok(VersionedCredentialRecord::new(record, revision))
    }

    fn compare_and_swap_credential_record(
        &mut self,
        expected_revision: RecordRevision,
        record: &wallet::CredentialRecord,
    ) -> Result<wallet::CredentialRecordId, RuntimeError> {
        let id = record.id.clone();
        let current_revision =
            self.credential_revisions
                .get(id.as_str())
                .copied()
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::CredentialStoreRejected,
                ))?;
        if current_revision != expected_revision {
            return Err(RuntimeError::new(
                RuntimeErrorReason::CredentialRevisionConflict,
            ));
        }
        let revision = next_revision(
            Some(current_revision),
            RuntimeErrorReason::CredentialStoreRejected,
        )?;
        self.credentials
            .insert(id.as_str().to_owned(), record.clone());
        self.credential_revisions
            .insert(id.as_str().to_owned(), revision);
        Ok(id)
    }

    fn delete_credential_record(
        &mut self,
        id: &wallet::CredentialRecordId,
        expected_revision: RecordRevision,
    ) -> Result<(), RuntimeError> {
        let current_revision =
            self.credential_revisions
                .get(id.as_str())
                .copied()
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::CredentialStoreRejected,
                ))?;
        if current_revision != expected_revision {
            return Err(RuntimeError::new(
                RuntimeErrorReason::CredentialRevisionConflict,
            ));
        }
        self.credentials.remove(id.as_str());
        self.credential_revisions.remove(id.as_str());
        Ok(())
    }

    fn claim_presentation_copy(
        &mut self,
        _credential_id: &wallet::CredentialRecordId,
        _copy_id: &wallet::PresentationCopyId,
        _policy: reallyme_wallet_runtime::PresentationCopyClaimPolicy,
        _prepared_claim_selector_digest: Option<&[u8; 32]>,
    ) -> Result<wallet::OnceOnlyPresentationCopy, RuntimeError> {
        Err(RuntimeError::new(
            RuntimeErrorReason::PresentationCopyStoreRejected,
        ))
    }

    fn append_transaction_log(
        &mut self,
        _entry: wallet::TransactionLogEntry,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn append_qtsp_decision(
        &mut self,
        _record: wallet::QtspDecisionRecord,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn save_flow_snapshot(
        &mut self,
        snapshot: wallet::FlowSnapshot,
        expected_revision: Option<RecordRevision>,
    ) -> Result<FlowSnapshotWriteResult, RuntimeError> {
        let id = snapshot.id.clone();
        let current_revision = self.snapshot_revisions.get(id.as_str()).copied();
        if current_revision != expected_revision {
            return Err(RuntimeError::new(
                RuntimeErrorReason::FlowSnapshotRevisionConflict,
            ));
        }
        let revision = next_revision(
            current_revision,
            RuntimeErrorReason::FlowSnapshotStoreRejected,
        )?;
        self.snapshots.insert(id.as_str().to_owned(), snapshot);
        self.snapshot_revisions
            .insert(id.as_str().to_owned(), revision);
        Ok(FlowSnapshotWriteResult::new(id, revision))
    }

    fn get_flow_snapshot(
        &mut self,
        id: &wallet::FlowSnapshotId,
    ) -> Result<VersionedFlowSnapshot, RuntimeError> {
        let snapshot = self
            .snapshots
            .get(id.as_str())
            .cloned()
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::FlowSnapshotStoreRejected,
            ))?;
        let revision =
            self.snapshot_revisions
                .get(id.as_str())
                .copied()
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::FlowSnapshotStoreRejected,
                ))?;
        Ok(VersionedFlowSnapshot::new(snapshot, revision))
    }

    fn create_wallet_lifecycle_record(
        &mut self,
        record: lifecycle::WalletLifecycleRecord,
    ) -> Result<wallet::NonEmptyIdentifier, RuntimeError> {
        let id = record.wallet_instance_id().clone();
        if self.lifecycles.contains_key(id.as_str()) {
            return Err(RuntimeError::new(
                RuntimeErrorReason::LifecycleAlreadyExists,
            ));
        }
        let revision = RecordRevision::new(1);
        self.lifecycles.insert(id.as_str().to_owned(), record);
        self.lifecycle_revisions
            .insert(id.as_str().to_owned(), revision);
        Ok(id)
    }

    fn get_wallet_lifecycle_record(
        &mut self,
        wallet_instance_id: &wallet::NonEmptyIdentifier,
    ) -> Result<VersionedWalletLifecycleRecord, RuntimeError> {
        let record = self
            .lifecycles
            .get(wallet_instance_id.as_str())
            .cloned()
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::LifecycleStoreRejected,
            ))?;
        let revision = self
            .lifecycle_revisions
            .get(wallet_instance_id.as_str())
            .copied()
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::LifecycleStoreRejected,
            ))?;
        Ok(VersionedWalletLifecycleRecord::new(record, revision))
    }

    fn compare_and_swap_wallet_lifecycle_record(
        &mut self,
        expected_revision: RecordRevision,
        record: &lifecycle::WalletLifecycleRecord,
        evidence: &lifecycle::WalletLifecycleEvidenceRecord,
    ) -> Result<wallet::NonEmptyIdentifier, RuntimeError> {
        let id = record.wallet_instance_id().clone();
        if record.last_evidence() != Some(evidence) || evidence.wallet_instance_id != id {
            return Err(RuntimeError::new(
                RuntimeErrorReason::LifecycleStoreRejected,
            ));
        }
        let current_revision =
            self.lifecycle_revisions
                .get(id.as_str())
                .copied()
                .ok_or(RuntimeError::new(
                    RuntimeErrorReason::LifecycleStoreRejected,
                ))?;
        if current_revision != expected_revision {
            return Err(RuntimeError::new(
                RuntimeErrorReason::LifecycleRevisionConflict,
            ));
        }
        let revision = next_revision(
            Some(current_revision),
            RuntimeErrorReason::LifecycleStoreRejected,
        )?;
        self.lifecycles
            .insert(id.as_str().to_owned(), record.clone());
        self.lifecycle_revisions
            .insert(id.as_str().to_owned(), revision);
        Ok(id)
    }
}

fn next_revision(
    current: Option<RecordRevision>,
    exhausted_reason: RuntimeErrorReason,
) -> Result<RecordRevision, RuntimeError> {
    let current_value = current.map_or(0, RecordRevision::value);
    current_value
        .checked_add(1)
        .map(RecordRevision::new)
        .ok_or(RuntimeError::new(exhausted_reason))
}
