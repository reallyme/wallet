// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adapt the versioned provider protobuf protocol to `WalletRuntimeBackend`.

use buffa::{EnumValue, MessageField};
use reallyme_wallet_lifecycle::{
    ensure_wallet_operation_allowed, WalletLifecycleEvent, WalletLifecycleEvidenceRecord,
    WalletLifecycleRecord, WalletOperation,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    credential_record_from_proto, credential_record_to_proto, flow_snapshot_from_proto,
    flow_snapshot_to_proto, presentation_copy_from_proto, qtsp_decision_record_to_proto,
    transaction_log_entry_to_proto, wallet_lifecycle_evidence_record_to_proto,
    wallet_lifecycle_record_from_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_runtime::{
    FlowSnapshotWriteResult, OperationIdempotencyKey, OperationReplayDecision,
    OperationRequestDigest, OperationReservation as RuntimeOperationReservation,
    PresentationCopyClaimPolicy, RecordRevision, RuntimeError, RuntimeErrorReason, RuntimeResult,
    VersionedCredentialRecord, VersionedFlowSnapshot, VersionedWalletLifecycleRecord,
    WalletRuntimeBackend,
};
use reallyme_wallet_types::{
    BatchCopyState, CredentialRecord, CredentialRecordId, FlowSnapshot, FlowSnapshotId,
    NonEmptyIdentifier, OnceOnlyPresentationCopy, PresentationCopyId, QtspDecisionRecord,
    TransactionLogEntry, UnixTimestamp,
};
use zeroize::Zeroizing;

use crate::provider_backend::ProtobufProviderBackend;
use crate::provider_call_support::{
    provider_request, require_revision, revision_to_proto, runtime_rejected,
};
use crate::{ProviderMethod, ProviderTransport};

impl<T, M> WalletRuntimeBackend for ProtobufProviderBackend<T, M>
where
    T: ProviderTransport,
{
    fn authorize_wallet_operation(&mut self, operation: WalletOperation) -> RuntimeResult<()> {
        let wallet_instance_id = self.wallet_instance_id.clone().ok_or(RuntimeError::new(
            RuntimeErrorReason::LifecycleStoreRejected,
        ))?;
        let (record, _revision) = self
            .get_wallet_lifecycle_record(&wallet_instance_id)?
            .into_parts();
        ensure_wallet_operation_allowed(&record, operation)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied))
    }

    fn bound_wallet_instance_id(&self) -> Option<NonEmptyIdentifier> {
        self.wallet_instance_id.clone()
    }

    fn trusted_now(&mut self) -> RuntimeResult<UnixTimestamp> {
        let rejected = || runtime_rejected(ProviderMethod::ReadTrustedTime);
        if let Some(clock) = self.trusted_clock.as_ref() {
            return clock.trusted_now().map_err(|_| rejected());
        }
        let request = pb::ReadTrustedTimeProviderRequest::default();
        match self
            .call(provider_request(request.into()))
            .map_err(|_| rejected())?
        {
            pb::wallet_provider_result::Result::ReadTrustedTime(response) => {
                let time = response.observed_at.as_option().ok_or_else(rejected)?;
                UnixTimestamp::from_seconds(time.seconds).map_err(|_| rejected())
            }
            _ => Err(rejected()),
        }
    }

    fn verify_wallet_lifecycle_authority(
        &mut self,
        current: &WalletLifecycleRecord,
        event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> RuntimeResult<()> {
        self.verify_lifecycle_authority(current, event, evidence, now)
    }

    fn reconcile_wallet_lifecycle_retry(
        &mut self,
        current: &WalletLifecycleRecord,
        event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> RuntimeResult<reallyme_wallet_lifecycle::ReconciledWalletLifecycleRetry> {
        self.reconcile_lifecycle_retry(current, event, evidence, now)
    }

    fn begin_idempotent_operation(
        &mut self,
        key: &OperationIdempotencyKey,
        request_digest: &OperationRequestDigest,
    ) -> RuntimeResult<OperationReplayDecision> {
        let request = pb::BeginOperationProviderRequest {
            idempotency_key: key.as_bytes().to_vec(),
            request_digest: request_digest.as_bytes().to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::BeginOperation(mut response) => {
                match response.outcome.take() {
                    Some(pb::begin_operation_provider_response::Outcome::Execute(reservation))
                        if reservation.value != 0 =>
                    {
                        RuntimeOperationReservation::from_provider_value(reservation.value)
                            .map(OperationReplayDecision::Execute)
                            .map_err(|_| {
                                RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected)
                            })
                    }
                    Some(pb::begin_operation_provider_response::Outcome::Replay(mut replay)) => {
                        Ok(OperationReplayDecision::Replay(Zeroizing::new(
                            core::mem::take(&mut replay.response),
                        )))
                    }
                    Some(pb::begin_operation_provider_response::Outcome::Execute(_)) | None => Err(
                        RuntimeError::new(RuntimeErrorReason::IdempotencyStoreRejected),
                    ),
                }
            }
            _ => Err(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            )),
        }
    }

    fn commit_idempotent_operation(
        &mut self,
        reservation: &RuntimeOperationReservation,
        response: &[u8],
    ) -> RuntimeResult<()> {
        let request = pb::CommitOperationProviderRequest {
            reservation: MessageField::some(pb::OperationReservation {
                value: reservation.value(),
                ..Default::default()
            }),
            response: response.to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::CommitOperation(_) => Ok(()),
            _ => Err(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            )),
        }
    }

    fn create_credential_record(
        &mut self,
        record: CredentialRecord,
    ) -> RuntimeResult<CredentialRecordId> {
        let expected_id = record.id.clone();
        let request = pb::CreateCredentialProviderRequest {
            record: MessageField::some(credential_record_to_proto(&record)),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::CreateCredential(mut response) => {
                let returned_id =
                    CredentialRecordId::new(core::mem::take(&mut response.credential_id))
                        .map_err(|_| runtime_rejected(ProviderMethod::CreateCredential))?;
                require_revision(&response.revision, ProviderMethod::CreateCredential)?;
                if returned_id != expected_id {
                    return Err(runtime_rejected(ProviderMethod::CreateCredential));
                }
                Ok(returned_id)
            }
            _ => Err(runtime_rejected(ProviderMethod::CreateCredential)),
        }
    }

    fn get_credential_record(
        &mut self,
        id: &CredentialRecordId,
    ) -> RuntimeResult<VersionedCredentialRecord> {
        let request = pb::GetCredentialProviderRequest {
            credential_id: id.as_str().to_owned(),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::GetCredential(response) => {
                let record = response
                    .record
                    .as_option()
                    .ok_or_else(|| runtime_rejected(ProviderMethod::GetCredential))
                    .and_then(|record| {
                        credential_record_from_proto(record)
                            .map_err(|_| runtime_rejected(ProviderMethod::GetCredential))
                    })?;
                let revision = require_revision(&response.revision, ProviderMethod::GetCredential)?;
                if &record.id != id {
                    return Err(runtime_rejected(ProviderMethod::GetCredential));
                }
                Ok(VersionedCredentialRecord::new(record, revision))
            }
            _ => Err(runtime_rejected(ProviderMethod::GetCredential)),
        }
    }

    fn compare_and_swap_credential_record(
        &mut self,
        expected_revision: RecordRevision,
        record: &CredentialRecord,
    ) -> RuntimeResult<CredentialRecordId> {
        let request = pb::CompareAndSwapCredentialProviderRequest {
            record: MessageField::some(credential_record_to_proto(record)),
            expected_revision: MessageField::some(revision_to_proto(expected_revision)),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::CompareAndSwapCredential(mut response) => {
                let returned_id =
                    CredentialRecordId::new(core::mem::take(&mut response.credential_id))
                        .map_err(|_| runtime_rejected(ProviderMethod::CompareAndSwapCredential))?;
                let revision =
                    require_revision(&response.revision, ProviderMethod::CompareAndSwapCredential)?;
                if returned_id != record.id || revision <= expected_revision {
                    return Err(runtime_rejected(ProviderMethod::CompareAndSwapCredential));
                }
                Ok(returned_id)
            }
            _ => Err(runtime_rejected(ProviderMethod::CompareAndSwapCredential)),
        }
    }

    fn delete_credential_record(
        &mut self,
        id: &CredentialRecordId,
        expected_revision: RecordRevision,
    ) -> RuntimeResult<()> {
        let request = pb::DeleteCredentialProviderRequest {
            credential_id: id.as_str().to_owned(),
            expected_revision: MessageField::some(revision_to_proto(expected_revision)),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::DeleteCredential(_) => Ok(()),
            _ => Err(runtime_rejected(ProviderMethod::DeleteCredential)),
        }
    }

    fn claim_presentation_copy(
        &mut self,
        credential_id: &CredentialRecordId,
        copy_id: &PresentationCopyId,
        policy: PresentationCopyClaimPolicy,
        prepared_claim_selector_digest: Option<&[u8; 32]>,
    ) -> RuntimeResult<OnceOnlyPresentationCopy> {
        match (policy, prepared_claim_selector_digest) {
            (PresentationCopyClaimPolicy::Generic, None) => {}
            (PresentationCopyClaimPolicy::ActiveZkCredential, Some(digest))
                if digest.iter().any(|byte| *byte != 0) => {}
            _ => return Err(runtime_rejected(ProviderMethod::ClaimPresentationCopy)),
        }
        let request = pb::ClaimPresentationCopyProviderRequest {
            credential_id: credential_id.as_str().to_owned(),
            copy_id: copy_id.as_str().to_owned(),
            prepared_claim_selector_digest: prepared_claim_selector_digest
                .map_or_else(Vec::new, |digest| digest.to_vec()),
            policy: EnumValue::from(match policy {
                PresentationCopyClaimPolicy::Generic => {
                    pb::PresentationCopyClaimPolicy::PRESENTATION_COPY_CLAIM_POLICY_GENERIC
                }
                PresentationCopyClaimPolicy::ActiveZkCredential => {
                    pb::PresentationCopyClaimPolicy::PRESENTATION_COPY_CLAIM_POLICY_ACTIVE_ZK_CREDENTIAL
                }
            }),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::ClaimPresentationCopy(response) => {
                let copy = response
                    .copy
                    .as_option()
                    .ok_or_else(|| runtime_rejected(ProviderMethod::ClaimPresentationCopy))
                    .and_then(|copy| {
                        presentation_copy_from_proto(copy)
                            .map_err(|_| runtime_rejected(ProviderMethod::ClaimPresentationCopy))
                    })?;
                if copy.credential_id != *credential_id
                    || copy.id != *copy_id
                    || copy.state != BatchCopyState::Claimed
                    || (policy == PresentationCopyClaimPolicy::Generic
                        && copy.prepared_claim_selector_digest.is_some())
                    || (policy == PresentationCopyClaimPolicy::ActiveZkCredential
                        && copy.prepared_claim_selector_digest
                            != prepared_claim_selector_digest.copied())
                    || !self
                        .claimed_presentation_copy_ids
                        .insert(copy.credential_id.clone(), copy.id.clone())
                {
                    return Err(runtime_rejected(ProviderMethod::ClaimPresentationCopy));
                }
                Ok(copy)
            }
            _ => Err(runtime_rejected(ProviderMethod::ClaimPresentationCopy)),
        }
    }

    fn append_transaction_log(&mut self, entry: TransactionLogEntry) -> RuntimeResult<()> {
        let request = pb::AppendTransactionLogProviderRequest {
            entry: MessageField::some(transaction_log_entry_to_proto(&entry)),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::AppendTransactionLog(_) => Ok(()),
            _ => Err(runtime_rejected(ProviderMethod::AppendTransactionLog)),
        }
    }

    fn append_qtsp_decision(&mut self, record: QtspDecisionRecord) -> RuntimeResult<()> {
        let request = pb::AppendQtspDecisionProviderRequest {
            record: MessageField::some(qtsp_decision_record_to_proto(&record)),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::AppendQtspDecision(_) => Ok(()),
            _ => Err(runtime_rejected(ProviderMethod::AppendQtspDecision)),
        }
    }

    fn save_flow_snapshot(
        &mut self,
        snapshot: FlowSnapshot,
        expected_revision: Option<RecordRevision>,
    ) -> RuntimeResult<FlowSnapshotWriteResult> {
        let expected_id = snapshot.id.clone();
        let request = pb::SaveFlowSnapshotProviderRequest {
            snapshot: MessageField::some(flow_snapshot_to_proto(&snapshot)),
            expected_revision: expected_revision
                .map(revision_to_proto)
                .map_or_else(MessageField::none, MessageField::some),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::SaveFlowSnapshot(mut response) => {
                let returned_id =
                    FlowSnapshotId::new(core::mem::take(&mut response.snapshot_id))
                        .map_err(|_| runtime_rejected(ProviderMethod::SaveFlowSnapshot))?;
                let revision =
                    require_revision(&response.revision, ProviderMethod::SaveFlowSnapshot)?;
                if returned_id != expected_id
                    || expected_revision.is_some_and(|expected| revision <= expected)
                {
                    return Err(runtime_rejected(ProviderMethod::SaveFlowSnapshot));
                }
                Ok(FlowSnapshotWriteResult::new(returned_id, revision))
            }
            _ => Err(runtime_rejected(ProviderMethod::SaveFlowSnapshot)),
        }
    }

    fn get_flow_snapshot(&mut self, id: &FlowSnapshotId) -> RuntimeResult<VersionedFlowSnapshot> {
        let request = pb::GetFlowSnapshotProviderRequest {
            snapshot_id: id.as_str().to_owned(),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::GetFlowSnapshot(response) => {
                let snapshot = response
                    .snapshot
                    .as_option()
                    .ok_or_else(|| runtime_rejected(ProviderMethod::GetFlowSnapshot))
                    .and_then(|snapshot| {
                        flow_snapshot_from_proto(snapshot)
                            .map_err(|_| runtime_rejected(ProviderMethod::GetFlowSnapshot))
                    })?;
                let revision =
                    require_revision(&response.revision, ProviderMethod::GetFlowSnapshot)?;
                if &snapshot.id != id {
                    return Err(runtime_rejected(ProviderMethod::GetFlowSnapshot));
                }
                Ok(VersionedFlowSnapshot::new(snapshot, revision))
            }
            _ => Err(runtime_rejected(ProviderMethod::GetFlowSnapshot)),
        }
    }

    fn create_wallet_lifecycle_record(
        &mut self,
        record: WalletLifecycleRecord,
    ) -> RuntimeResult<NonEmptyIdentifier> {
        let expected_id = record.wallet_instance_id().clone();
        let request = pb::CreateWalletLifecycleProviderRequest {
            record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::CreateWalletLifecycle(mut response) => {
                let returned_id =
                    NonEmptyIdentifier::new(core::mem::take(&mut response.wallet_instance_id))
                        .map_err(|_| runtime_rejected(ProviderMethod::CreateWalletLifecycle))?;
                require_revision(&response.revision, ProviderMethod::CreateWalletLifecycle)?;
                if returned_id != expected_id {
                    return Err(runtime_rejected(ProviderMethod::CreateWalletLifecycle));
                }
                Ok(returned_id)
            }
            _ => Err(runtime_rejected(ProviderMethod::CreateWalletLifecycle)),
        }
    }

    fn get_wallet_lifecycle_record(
        &mut self,
        wallet_instance_id: &NonEmptyIdentifier,
    ) -> RuntimeResult<VersionedWalletLifecycleRecord> {
        let request = pb::GetWalletLifecycleProviderRequest {
            wallet_instance_id: wallet_instance_id.as_str().to_owned(),
            __buffa_unknown_fields: Default::default(),
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::GetWalletLifecycle(response) => {
                let record = response
                    .record
                    .as_option()
                    .ok_or_else(|| runtime_rejected(ProviderMethod::GetWalletLifecycle))
                    .and_then(|record| {
                        wallet_lifecycle_record_from_proto(record)
                            .map_err(|_| runtime_rejected(ProviderMethod::GetWalletLifecycle))
                    })?;
                let revision =
                    require_revision(&response.revision, ProviderMethod::GetWalletLifecycle)?;
                if record.wallet_instance_id() != wallet_instance_id {
                    return Err(runtime_rejected(ProviderMethod::GetWalletLifecycle));
                }
                Ok(VersionedWalletLifecycleRecord::new(record, revision))
            }
            _ => Err(runtime_rejected(ProviderMethod::GetWalletLifecycle)),
        }
    }

    fn compare_and_swap_wallet_lifecycle_record(
        &mut self,
        expected_revision: RecordRevision,
        record: &WalletLifecycleRecord,
        evidence: &WalletLifecycleEvidenceRecord,
    ) -> RuntimeResult<NonEmptyIdentifier> {
        if record.last_evidence() != Some(evidence)
            || evidence.wallet_instance_id != *record.wallet_instance_id()
        {
            return Err(runtime_rejected(
                ProviderMethod::CompareAndSwapWalletLifecycle,
            ));
        }
        let request = pb::CompareAndSwapWalletLifecycleProviderRequest {
            record: MessageField::some(wallet_lifecycle_record_to_proto(record)),
            expected_revision: MessageField::some(revision_to_proto(expected_revision)),
            evidence: MessageField::some(wallet_lifecycle_evidence_record_to_proto(evidence)),
            ..Default::default()
        };
        match self.call(provider_request(request.into()))? {
            pb::wallet_provider_result::Result::CompareAndSwapWalletLifecycle(mut response) => {
                let returned_id =
                    NonEmptyIdentifier::new(core::mem::take(&mut response.wallet_instance_id))
                        .map_err(|_| {
                            runtime_rejected(ProviderMethod::CompareAndSwapWalletLifecycle)
                        })?;
                let revision = require_revision(
                    &response.revision,
                    ProviderMethod::CompareAndSwapWalletLifecycle,
                )?;
                if &returned_id != record.wallet_instance_id() || revision <= expected_revision {
                    return Err(runtime_rejected(
                        ProviderMethod::CompareAndSwapWalletLifecycle,
                    ));
                }
                Ok(returned_id)
            }
            _ => Err(runtime_rejected(
                ProviderMethod::CompareAndSwapWalletLifecycle,
            )),
        }
    }
}
