// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated Wallet operation runtime handlers.

use std::collections::BTreeMap;

use crate::{
    FlowSnapshotWriteResult, OperationIdempotencyKey, OperationReplayDecision,
    OperationRequestDigest, OperationReservation, RecordRevision, RuntimeError, RuntimeErrorReason,
    VersionedCredentialRecord, VersionedFlowSnapshot, VersionedWalletLifecycleRecord,
    WalletCoreRuntime, WalletOperationExecutor, WalletRuntimeBackend,
};
use buffa::{EnumValue, Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_wallet_lifecycle as lifecycle;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    consent_scope_to_proto, credential_record_to_proto, credential_status_evidence_to_proto,
    flow_snapshot_to_proto, presentation_copy_to_proto, qtsp_decision_record_to_proto,
    transaction_log_entry_to_proto, verifier_entitlement_to_proto,
    wallet_lifecycle_evidence_record_to_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_proto_codec::decode::decode_wallet_operation_response;
use reallyme_wallet_proto_codec::encode::encode_wallet_operation_request;
use reallyme_wallet_proto_codec::{ProtoErrorReason, MAX_WALLET_PROTO_MESSAGE_BYTES};
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

enum JournalEntry {
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
struct MemoryBackend {
    credentials: BTreeMap<String, wallet::CredentialRecord>,
    credential_revisions: BTreeMap<String, RecordRevision>,
    copies: BTreeMap<String, wallet::OnceOnlyPresentationCopy>,
    snapshots: BTreeMap<String, wallet::FlowSnapshot>,
    snapshot_revisions: BTreeMap<String, RecordRevision>,
    lifecycles: BTreeMap<String, lifecycle::WalletLifecycleRecord>,
    lifecycle_revisions: BTreeMap<String, RecordRevision>,
    lifecycle_evidence_count: usize,
    transaction_log_count: usize,
    transaction_log_entries: Vec<wallet::TransactionLogEntry>,
    qtsp_decision_count: usize,
    credential_create_count: usize,
    lifecycle_create_count: usize,
    reject_credential_compare_and_swap: bool,
    advance_credential_revision_before_delete: bool,
    reject_lifecycle_compare_and_swap: bool,
    reject_lifecycle_evidence_append: bool,
    journal: BTreeMap<[u8; 32], JournalEntry>,
    reservation_keys: BTreeMap<u64, [u8; 32]>,
    next_reservation: u64,
    reject_journal_commit: bool,
    trusted_now_seconds: Option<i64>,
    trusted_now_after_first: Option<i64>,
    trusted_time_reads: usize,
    credential_replacement_during_claim: Option<wallet::CredentialRecord>,
    trusted_lifecycle_authority: Option<String>,
    lifecycle_authority_checks: usize,
    allow_retry_reconciliation: bool,
    bound_wallet_override: Option<&'static str>,
}

impl WalletRuntimeBackend for MemoryBackend {
    fn authorize_wallet_operation(
        &mut self,
        operation: lifecycle::WalletOperation,
    ) -> Result<(), RuntimeError> {
        let record = self
            .lifecycles
            .get("wallet-unit-1")
            .ok_or(RuntimeError::new(
                RuntimeErrorReason::LifecycleStoreRejected,
            ))?;
        lifecycle::ensure_wallet_operation_allowed(record, operation)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied))
    }

    fn bound_wallet_instance_id(&self) -> Option<wallet::NonEmptyIdentifier> {
        wallet::NonEmptyIdentifier::new(
            self.bound_wallet_override
                .unwrap_or("wallet-unit-1")
                .to_owned(),
        )
        .ok()
    }

    fn trusted_now(&mut self) -> Result<wallet::UnixTimestamp, RuntimeError> {
        retry_tests::trusted_now(self)
    }

    fn verify_wallet_lifecycle_authority(
        &mut self,
        _current: &lifecycle::WalletLifecycleRecord,
        _event: lifecycle::WalletLifecycleEvent,
        evidence: &lifecycle::WalletLifecycleEvidenceRecord,
        _now: wallet::UnixTimestamp,
    ) -> Result<(), RuntimeError> {
        self.lifecycle_authority_checks = self.lifecycle_authority_checks.saturating_add(1);
        match self.trusted_lifecycle_authority.as_deref() {
            Some(trusted) if trusted == evidence.authority_id.as_str() => Ok(()),
            _ => Err(RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied)),
        }
    }

    fn reconcile_wallet_lifecycle_retry(
        &mut self,
        current: &lifecycle::WalletLifecycleRecord,
        event: lifecycle::WalletLifecycleEvent,
        evidence: &lifecycle::WalletLifecycleEvidenceRecord,
        now: wallet::UnixTimestamp,
    ) -> Result<lifecycle::ReconciledWalletLifecycleRetry, RuntimeError> {
        retry_tests::reconcile(self, current, event, evidence, now)
    }

    fn begin_idempotent_operation(
        &mut self,
        key: &OperationIdempotencyKey,
        request_digest: &OperationRequestDigest,
    ) -> Result<OperationReplayDecision, RuntimeError> {
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
        if self.reject_journal_commit {
            return Err(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            ));
        }
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
        self.credential_create_count = self.credential_create_count.saturating_add(1);
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
        if self.reject_credential_compare_and_swap {
            return Err(RuntimeError::new(
                RuntimeErrorReason::CredentialRevisionConflict,
            ));
        }
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
        if self.advance_credential_revision_before_delete {
            let advanced = next_revision(
                Some(current_revision),
                RuntimeErrorReason::CredentialStoreRejected,
            )?;
            self.credential_revisions
                .insert(id.as_str().to_owned(), advanced);
            return Err(RuntimeError::new(
                RuntimeErrorReason::CredentialRevisionConflict,
            ));
        }
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
        credential_id: &wallet::CredentialRecordId,
        copy_id: &wallet::PresentationCopyId,
        policy: reallyme_wallet_storage::PresentationCopyClaimPolicy,
        _prepared_claim_selector_digest: Option<&[u8; 32]>,
    ) -> Result<wallet::OnceOnlyPresentationCopy, RuntimeError> {
        if policy != reallyme_wallet_storage::PresentationCopyClaimPolicy::Generic {
            return Err(RuntimeError::new(
                RuntimeErrorReason::PresentationCopyStoreRejected,
            ));
        }
        if let Some(replacement) = self.credential_replacement_during_claim.take() {
            self.credentials
                .insert(credential_id.as_str().to_owned(), replacement);
        }
        match self.copies.get(credential_id.as_str()) {
            Some(copy) if copy.id == *copy_id => {
                self.copies
                    .remove(credential_id.as_str())
                    .ok_or(RuntimeError::new(
                        RuntimeErrorReason::PresentationCopyStoreRejected,
                    ))
            }
            _ => Err(RuntimeError::new(
                RuntimeErrorReason::PresentationCopyStoreRejected,
            )),
        }
    }

    fn append_transaction_log(
        &mut self,
        entry: wallet::TransactionLogEntry,
    ) -> Result<(), RuntimeError> {
        let next_sequence = u64::try_from(self.transaction_log_entries.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(RuntimeError::new(RuntimeErrorReason::LogStoreRejected))?;
        let expected_previous_hash = self
            .transaction_log_entries
            .last()
            .map_or([0; wallet::TRANSACTION_LOG_HASH_BYTES], |head| {
                head.entry_hash
            });
        if entry.sequence != next_sequence
            || entry.previous_entry_hash != expected_previous_hash
            || self
                .transaction_log_entries
                .iter()
                .any(|stored| stored.id == entry.id)
        {
            return Err(RuntimeError::new(RuntimeErrorReason::LogStoreRejected));
        }
        self.transaction_log_entries.push(entry);
        self.transaction_log_count = self.transaction_log_count.saturating_add(1);
        Ok(())
    }

    fn append_qtsp_decision(
        &mut self,
        _record: wallet::QtspDecisionRecord,
    ) -> Result<(), RuntimeError> {
        self.qtsp_decision_count = self.qtsp_decision_count.saturating_add(1);
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
        self.lifecycle_create_count = self.lifecycle_create_count.saturating_add(1);
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
        if self.reject_lifecycle_compare_and_swap {
            return Err(RuntimeError::new(
                RuntimeErrorReason::LifecycleRevisionConflict,
            ));
        }
        let id = record.wallet_instance_id().clone();
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
        if record.last_evidence() != Some(evidence)
            || evidence.wallet_instance_id != id
            || self.reject_lifecycle_evidence_append
        {
            return Err(RuntimeError::new(
                RuntimeErrorReason::LifecycleEvidenceStoreRejected,
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
        self.lifecycle_evidence_count = self.lifecycle_evidence_count.saturating_add(1);
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

fn mutating_operation_request(
    operation: pb::wallet_operation_request::Operation,
) -> pb::WalletOperationRequest {
    let mut request = pb::WalletOperationRequest::default();
    request.idempotency_key = vec![0xA5; 32];
    request.operation = Some(operation);
    request
}

fn read_operation_request(
    operation: pb::wallet_operation_request::Operation,
) -> pb::WalletOperationRequest {
    let mut request = pb::WalletOperationRequest::default();
    request.operation = Some(operation);
    request
}

fn create_lifecycle_operation_request(
    key_byte: u8,
    wallet_instance_id: &str,
) -> Result<pb::WalletOperationRequest, wallet::WalletTypesError> {
    let record = lifecycle::new_wallet_lifecycle(id(wallet_instance_id)?, timestamp_at(10)?);
    let mut request = pb::WalletOperationRequest::default();
    request.idempotency_key = vec![key_byte; 32];
    request.operation = pb::PutWalletLifecycleRecordRequest {
        record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
        ..Default::default()
    }
    .into();
    Ok(request)
}

fn response_has_runtime_reason(
    response: &pb::WalletOperationResponse,
    coarse: pb::WalletErrorReason,
    detail: pb::RuntimeErrorReason,
) -> bool {
    matches!(
        response.outcome.as_ref(),
        Some(pb::wallet_operation_response::Outcome::Error(error))
            if matches!(
                error.wallet.as_option(),
                Some(wallet_error)
                    if wallet_error.reason.as_known() == Some(coarse)
                        && matches!(
                            &wallet_error.detail,
                            Some(pb::wallet_error::Detail::Runtime(reason))
                                if reason.as_known() == Some(detail)
                        )
            )
    )
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    timestamp_at(1)
}

fn timestamp_at(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

fn encrypted_record() -> Result<wallet::EncryptedRecord, wallet::WalletTypesError> {
    Ok(wallet::EncryptedRecord {
        header: wallet::EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp()?,
        },
        nonce: vec![1; 12],
        aad: vec![2],
        ciphertext: vec![3; 16],
    })
}

fn credential_record() -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    credential_record_with_status(wallet::CredentialStatus::Active)
}

fn credential_record_with_status(
    status: wallet::CredentialStatus,
) -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    Ok(wallet::CredentialRecord::new(
        id("credential-1")?,
        id("issuer-1")?,
        None,
        None,
        Some(wallet::CredentialStatusReference::new(
            wallet::SignedCredentialIssuer::new("issuer-1".to_owned())?,
            [9; 32],
            0,
            None,
        )),
        wallet::CredentialFormat::SdJwtVc,
        status,
        timestamp()?,
        encrypted_record()?,
    ))
}

fn credential_status_evidence() -> Result<wallet::CredentialStatusEvidence, wallet::WalletTypesError>
{
    Ok(wallet::CredentialStatusEvidence {
        credential_id: id("credential-1")?,
        observed_status: wallet::CredentialStatus::Suspended,
        method: wallet::CredentialStatusEvidenceMethod::TokenStatusList,
        source_issuer: wallet::SignedCredentialIssuer::new("issuer-1".to_owned())?,
        source_list_id: [9; 32],
        status_index: 0,
        source_issued_at: timestamp_at(9)?,
        checked_at: timestamp_at(10)?,
        valid_until: timestamp_at(20)?,
    })
}

fn presentation_copy() -> Result<wallet::OnceOnlyPresentationCopy, wallet::WalletTypesError> {
    Ok(wallet::OnceOnlyPresentationCopy {
        id: id("copy-1")?,
        credential_id: id("credential-1")?,
        prepared_claim_selector_digest: None,
        state: wallet::BatchCopyState::Claimed,
        encrypted_payload: encrypted_record()?,
    })
}

fn flow_snapshot() -> Result<wallet::FlowSnapshot, wallet::WalletTypesError> {
    Ok(wallet::FlowSnapshot {
        id: id("flow-1")?,
        kind: wallet::FlowKind::Issuance,
        state: issuance_flow_state(
            pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_OFFER_RECEIVED,
        ),
        state_schema_version: wallet::FlowStateSchemaVersion::V1,
        updated_at: timestamp()?,
    })
}

fn issuance_flow_state(stage: pb::OpenId4VciIssuanceStage) -> Vec<u8> {
    let mut state = pb::OpenId4VciIssuanceSnapshot::default();
    state.stage = EnumValue::from(stage);
    let offer = openid4vci_pb::CredentialOffer {
        credential_issuer: "https://issuer.example".to_owned(),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: MessageField::none(),
        __buffa_unknown_fields: Default::default(),
    };
    state.credential_offer = MessageField::some(offer);
    state.encode_to_vec()
}

fn wallet_lifecycle_record() -> Result<lifecycle::WalletLifecycleRecord, TestError> {
    let evidence = lifecycle::WalletLifecycleEvidenceRecord {
        id: id("lifecycle-state-evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: lifecycle::WalletLifecycleEvidenceKind::Provisioning,
        event: lifecycle::WalletLifecycleEvent::BeginProvisioning,
        occurred_at: timestamp_at(10)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("provisioning-evidence-1")?,
        evidence_digest: vec![1, 3, 3, 7],
    };
    Ok(lifecycle::restore_wallet_lifecycle(
        id("wallet-unit-1")?,
        lifecycle::WalletLifecycleState::Provisioning,
        timestamp_at(10)?,
        Some(lifecycle::WalletLifecycleEvent::BeginProvisioning),
        None,
        None,
        Some(evidence),
    )?)
}

fn active_backend() -> Result<MemoryBackend, TestError> {
    let evidence = wallet_lifecycle_evidence_record()?;
    let record = lifecycle::apply_wallet_lifecycle_event(
        wallet_lifecycle_record()?,
        lifecycle::WalletLifecycleEvent::CompleteProvisioning,
        timestamp_at(11)?,
        Some(&evidence),
    )?;
    let mut backend = MemoryBackend::default();
    backend
        .lifecycles
        .insert("wallet-unit-1".to_owned(), record);
    Ok(backend)
}

fn backend_with_credential(status: wallet::CredentialStatus) -> Result<MemoryBackend, TestError> {
    let mut backend = active_backend()?;
    backend.credentials.insert(
        "credential-1".to_owned(),
        credential_record_with_status(status)?,
    );
    backend
        .credential_revisions
        .insert("credential-1".to_owned(), RecordRevision::new(1));
    Ok(backend)
}

fn transition_backend(
    backend: &mut MemoryBackend,
    event: lifecycle::WalletLifecycleEvent,
    kind: lifecycle::WalletLifecycleEvidenceKind,
    at_seconds: i64,
) -> Result<(), TestError> {
    let previous = backend
        .lifecycles
        .get("wallet-unit-1")
        .cloned()
        .ok_or(TestError::MissingResponseField)?;
    let evidence = lifecycle::WalletLifecycleEvidenceRecord {
        id: id(&format!(
            "lifecycle-transition-evidence-{event:?}-{at_seconds}"
        ))?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind,
        event,
        occurred_at: timestamp_at(at_seconds)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("lifecycle-transition-reference")?,
        evidence_digest: vec![2, 4, 6, 8],
    };
    let next = lifecycle::apply_wallet_lifecycle_event(
        previous,
        event,
        timestamp_at(at_seconds)?,
        Some(&evidence),
    )?;
    backend.lifecycles.insert("wallet-unit-1".to_owned(), next);
    Ok(())
}

fn wallet_lifecycle_evidence_record(
) -> Result<lifecycle::WalletLifecycleEvidenceRecord, wallet::WalletTypesError> {
    Ok(lifecycle::WalletLifecycleEvidenceRecord {
        id: id("lifecycle-evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: lifecycle::WalletLifecycleEvidenceKind::Backup,
        event: lifecycle::WalletLifecycleEvent::CompleteProvisioning,
        occurred_at: timestamp_at(11)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("backup-evidence-1")?,
        evidence_digest: vec![1, 2, 3, 4],
    })
}

#[path = "handle_authority_tests.rs"]
mod authority_tests;

#[path = "handle_wallet_binding_tests.rs"]
mod wallet_binding_tests;

#[path = "handle_boundary_tests.rs"]
mod boundary_tests;

#[path = "handle_domain_tests.rs"]
mod domain_tests;

#[path = "handle_operation_tests.rs"]
mod operation_tests;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("missing_response_field")]
    MissingResponseField,
    #[error("runtime")]
    Runtime(#[from] RuntimeError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("wallet_log")]
    WalletLog(#[from] reallyme_wallet_log::WalletLogError),
    #[error("lifecycle")]
    Lifecycle(#[from] lifecycle::LifecycleError),
    #[error("operation_codec")]
    OperationCodec,
}

#[path = "handle_retry_tests.rs"]
mod retry_tests;
