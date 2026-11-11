// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handle generated request and response DTOs behind the operation union.

use buffa::MessageField;
use reallyme_wallet_lifecycle::{WalletLifecycleState, WalletOperation};
use reallyme_wallet_log::{validate_qtsp_decision_record, validate_transaction_log_entry};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    credential_record_to_proto, flow_snapshot_from_proto, flow_snapshot_to_proto,
    presentation_copy_to_proto, qtsp_decision_record_from_proto, transaction_log_entry_from_proto,
    wallet_lifecycle_record_from_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_types::{
    BatchCopyState, CredentialRecordId, FlowKind, FlowSnapshotId, NonEmptyIdentifier,
    PresentationCopyId,
};
use zeroize::Zeroizing;

use crate::authorize_audit_record::{require_record_time, transaction_history_operation};
use crate::require_active_credential::require_active_credential;
use crate::{
    RecordRevision, RuntimeError, RuntimeErrorReason, RuntimeResult, WalletRuntimeBackend,
};

/// Runtime engine core for generated Wallet operation DTOs.
pub struct WalletCoreRuntime<B> {
    backend: B,
}

impl<B> WalletCoreRuntime<B>
where
    B: WalletRuntimeBackend,
{
    /// Create a runtime around an injected backend.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Borrow the backend mutably.
    #[must_use]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Consume the runtime and return its backend.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }

    /// Reject raw credential receipt claims from the public wire protocol.
    ///
    /// A serialized record carries no proof that its issuer signature, trust
    /// decision, validity, or holder binding were verified. Persisting it would
    /// let a caller manufacture a credential with verified-looking state.
    pub(crate) fn put_credential_record(
        &mut self,
        _request: pb::PutCredentialRecordRequest,
    ) -> RuntimeResult<pb::PutCredentialRecordResponse> {
        Err(RuntimeError::new(RuntimeErrorReason::OperationUnsupported))
    }

    /// Handle the `GetCredentialRecord` operation variant.
    pub(crate) fn get_credential_record(
        &mut self,
        mut request: pb::GetCredentialRecordRequest,
    ) -> RuntimeResult<pb::GetCredentialRecordResponse> {
        let credential_id = CredentialRecordId::new(core::mem::take(&mut request.credential_id))
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        let (record, _revision) = self
            .backend
            .get_credential_record(&credential_id)?
            .into_parts();

        Ok(pb::GetCredentialRecordResponse {
            record: MessageField::some(credential_record_to_proto(&record)),
            ..Default::default()
        })
    }

    /// Handle the `DeleteCredentialRecord` operation variant.
    pub(crate) fn delete_credential_record(
        &mut self,
        mut request: pb::DeleteCredentialRecordRequest,
    ) -> RuntimeResult<pb::DeleteCredentialRecordResponse> {
        let credential_id = CredentialRecordId::new(core::mem::take(&mut request.credential_id))
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        let versioned = self.backend.get_credential_record(&credential_id)?;
        let expected_revision = versioned.revision();
        core::mem::drop(versioned);
        self.backend
            .authorize_wallet_operation(WalletOperation::DeleteWallet)?;
        self.backend
            .delete_credential_record(&credential_id, expected_revision)?;

        Ok(pb::DeleteCredentialRecordResponse::default())
    }

    /// Reject raw status claims that have no live verifier capability.
    ///
    /// The operation remains present in the stable v1 wire contract, but it
    /// cannot safely mutate inventory because a protobuf request cannot carry
    /// the trust capability used to verify a signed status source.
    pub(crate) fn apply_credential_status_evidence(
        &mut self,
        _request: pb::ApplyCredentialStatusEvidenceRequest,
    ) -> RuntimeResult<pb::ApplyCredentialStatusEvidenceResponse> {
        Err(RuntimeError::new(RuntimeErrorReason::OperationUnsupported))
    }

    /// Handle the `ClaimPresentationCopy` operation variant.
    pub(crate) fn claim_presentation_copy(
        &mut self,
        mut request: pb::ClaimPresentationCopyRequest,
    ) -> RuntimeResult<pb::ClaimPresentationCopyResponse> {
        let policy = match request.policy.as_known() {
            Some(pb::PresentationCopyClaimPolicy::PRESENTATION_COPY_CLAIM_POLICY_GENERIC) => {
                reallyme_wallet_storage::PresentationCopyClaimPolicy::Generic
            }
            Some(
                pb::PresentationCopyClaimPolicy::PRESENTATION_COPY_CLAIM_POLICY_ACTIVE_ZK_CREDENTIAL,
            ) => reallyme_wallet_storage::PresentationCopyClaimPolicy::ActiveZkCredential,
            _ => return Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest)),
        };
        let credential_id = CredentialRecordId::new(core::mem::take(&mut request.credential_id))
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        let copy_id = PresentationCopyId::new(core::mem::take(&mut request.copy_id))
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        let selector = match policy {
            reallyme_wallet_storage::PresentationCopyClaimPolicy::Generic => {
                if !request.prepared_claim_selector_digest.is_empty() {
                    return Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest));
                }
                None
            }
            reallyme_wallet_storage::PresentationCopyClaimPolicy::ActiveZkCredential => {
                let bytes =
                    Zeroizing::new(core::mem::take(&mut request.prepared_claim_selector_digest));
                if bytes.len() != 32 {
                    return Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest));
                }
                let mut digest = Zeroizing::new([0_u8; 32]);
                digest.copy_from_slice(bytes.as_slice());
                if digest.iter().all(|byte| *byte == 0) {
                    return Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest));
                }
                Some(digest)
            }
        };
        self.backend
            .authorize_wallet_operation(WalletOperation::PresentCredential)?;
        // The provider must check the parent credential inside the claim
        // transaction. The runtime also refuses to start a claim for a
        // credential it can observe as inactive, and refuses to release copy
        // bytes if the credential is no longer active once the claim returns.
        require_active_credential(
            &mut self.backend,
            &credential_id,
            RuntimeErrorReason::CredentialNotActive,
        )?;
        let copy = match self.backend.claim_presentation_copy(
            &credential_id,
            &copy_id,
            policy,
            selector.as_deref(),
        ) {
            Ok(copy) => copy,
            Err(error) => {
                // A provider refuses the claim when the credential became
                // inactive after the pre-check. Report that, not a store fault.
                require_active_credential(
                    &mut self.backend,
                    &credential_id,
                    RuntimeErrorReason::CredentialNotActive,
                )?;
                return Err(error);
            }
        };
        if copy.credential_id != credential_id
            || copy.id != copy_id
            || copy.state != BatchCopyState::Claimed
            || (policy == reallyme_wallet_storage::PresentationCopyClaimPolicy::Generic
                && copy.prepared_claim_selector_digest.is_some())
            || (policy == reallyme_wallet_storage::PresentationCopyClaimPolicy::ActiveZkCredential
                && copy.prepared_claim_selector_digest != selector.as_ref().map(|digest| **digest))
        {
            // The backend must commit the burn before any copy bytes cross the
            // runtime boundary. A provider can be injected directly here, so
            // this check cannot depend on the wire-provider adapter alone.
            return Err(RuntimeError::new(
                RuntimeErrorReason::PresentationCopyStoreRejected,
            ));
        }
        // A concurrent deletion or status change may have committed between
        // the pre-check and the claim. The copy is already burned, so failing
        // here leaves no presentable copy for an inactive credential.
        require_active_credential(
            &mut self.backend,
            &credential_id,
            RuntimeErrorReason::ClaimedCopyDiscarded,
        )?;

        Ok(pb::ClaimPresentationCopyResponse {
            copy: MessageField::some(presentation_copy_to_proto(&copy)),
            ..Default::default()
        })
    }

    /// The wire contract cannot authenticate registration evidence. Keep this
    /// legacy operation fail closed; certificate-backed preparation must use
    /// the consent boundary with an injected registration verifier.
    pub(crate) fn evaluate_verifier_entitlement(
        &self,
        _request: pb::EvaluateVerifierEntitlementRequest,
    ) -> RuntimeResult<pb::EvaluateVerifierEntitlementResponse> {
        Err(RuntimeError::new(RuntimeErrorReason::OperationUnsupported))
    }

    /// Handle the `AppendTransactionLog` operation variant.
    pub(crate) fn append_transaction_log(
        &mut self,
        request: pb::AppendTransactionLogRequest,
    ) -> RuntimeResult<pb::AppendTransactionLogResponse> {
        let entry = request
            .entry
            .as_option()
            .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
            .and_then(|entry| {
                transaction_log_entry_from_proto(entry).map_err(RuntimeError::from)
            })?;
        validate_transaction_log_entry(&entry)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        // Audit records are dated by the caller; refuse a date beyond the
        // accepted skew so the history cannot claim an event that trusted time
        // has not reached.
        require_record_time(entry.occurred_at, self.backend.trusted_now()?)?;
        self.backend
            .authorize_wallet_operation(transaction_history_operation(entry.purpose))?;
        self.backend.append_transaction_log(entry)?;

        Ok(pb::AppendTransactionLogResponse::default())
    }

    /// Handle the `AppendQtspDecision` operation variant.
    pub(crate) fn append_qtsp_decision(
        &mut self,
        request: pb::AppendQtspDecisionRequest,
    ) -> RuntimeResult<pb::AppendQtspDecisionResponse> {
        let record = request
            .record
            .as_option()
            .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
            .and_then(|record| {
                qtsp_decision_record_from_proto(record).map_err(RuntimeError::from)
            })?;
        validate_qtsp_decision_record(&record)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        require_record_time(record.decided_at, self.backend.trusted_now()?)?;
        self.backend
            .authorize_wallet_operation(WalletOperation::SignWithWalletKey)?;
        self.backend.append_qtsp_decision(record)?;

        Ok(pb::AppendQtspDecisionResponse::default())
    }

    /// Handle the `SaveFlowSnapshot` operation variant.
    pub(crate) fn save_flow_snapshot(
        &mut self,
        request: pb::SaveFlowSnapshotRequest,
    ) -> RuntimeResult<pb::SaveFlowSnapshotResponse> {
        // Revision zero names no stored record. Reject it rather than let a
        // provider guess whether it means create, any revision, or invalid.
        let expected_revision = request
            .expected_revision
            .as_option()
            .map(|revision| {
                if revision.value == 0 {
                    Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
                } else {
                    Ok(RecordRevision::new(revision.value))
                }
            })
            .transpose()?;
        let snapshot = request
            .snapshot
            .as_option()
            .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
            .and_then(|snapshot| flow_snapshot_from_proto(snapshot).map_err(RuntimeError::from))?;
        let operation = match snapshot.kind {
            FlowKind::Issuance => WalletOperation::BeginIssuance,
            FlowKind::Presentation => WalletOperation::PresentCredential,
        };
        self.backend.authorize_wallet_operation(operation)?;
        let (snapshot_id, revision) = self
            .backend
            .save_flow_snapshot(snapshot, expected_revision)?
            .into_parts();

        let mut response = pb::SaveFlowSnapshotResponse::default();
        response.snapshot_id = snapshot_id.as_str().to_owned();
        response.revision = MessageField::some(pb::RecordRevision {
            value: revision.value(),
            ..Default::default()
        });
        Ok(response)
    }

    /// Handle the `GetFlowSnapshot` operation variant.
    pub(crate) fn get_flow_snapshot(
        &mut self,
        mut request: pb::GetFlowSnapshotRequest,
    ) -> RuntimeResult<pb::GetFlowSnapshotResponse> {
        let snapshot_id = FlowSnapshotId::new(core::mem::take(&mut request.snapshot_id))
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        let (snapshot, revision) = self.backend.get_flow_snapshot(&snapshot_id)?.into_parts();

        Ok(pb::GetFlowSnapshotResponse {
            snapshot: MessageField::some(flow_snapshot_to_proto(&snapshot)),
            revision: MessageField::some(pb::RecordRevision {
                value: revision.value(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// Refuse lifecycle access for any Wallet Unit other than the one the
    /// backend is bound to.
    pub(crate) fn require_bound_wallet(
        &self,
        wallet_instance_id: &NonEmptyIdentifier,
    ) -> RuntimeResult<()> {
        match self.backend.bound_wallet_instance_id() {
            Some(bound) if &bound == wallet_instance_id => Ok(()),
            _ => Err(RuntimeError::new(RuntimeErrorReason::LifecyclePolicyDenied)),
        }
    }

    /// Handle the `PutWalletLifecycleRecord` operation variant.
    pub(crate) fn put_wallet_lifecycle_record(
        &mut self,
        request: pb::PutWalletLifecycleRecordRequest,
    ) -> RuntimeResult<pb::PutWalletLifecycleRecordResponse> {
        let record = request
            .record
            .as_option()
            .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
            .and_then(|record| {
                wallet_lifecycle_record_from_proto(record).map_err(RuntimeError::from)
            })?;
        if record.state() != WalletLifecycleState::Unprovisioned {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest));
        }
        self.require_bound_wallet(record.wallet_instance_id())?;
        if record.updated_at() > self.backend.trusted_now()? {
            return Err(RuntimeError::new(RuntimeErrorReason::LifecycleClockSkew));
        }
        let wallet_instance_id = self.backend.create_wallet_lifecycle_record(record)?;

        let mut response = pb::PutWalletLifecycleRecordResponse::default();
        response.wallet_instance_id = wallet_instance_id.as_str().to_owned();
        Ok(response)
    }

    /// Handle the `GetWalletLifecycleRecord` operation variant.
    pub(crate) fn get_wallet_lifecycle_record(
        &mut self,
        mut request: pb::GetWalletLifecycleRecordRequest,
    ) -> RuntimeResult<pb::GetWalletLifecycleRecordResponse> {
        let wallet_instance_id =
            NonEmptyIdentifier::new(core::mem::take(&mut request.wallet_instance_id))
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        self.require_bound_wallet(&wallet_instance_id)?;
        let (record, _revision) = self
            .backend
            .get_wallet_lifecycle_record(&wallet_instance_id)?
            .into_parts();

        Ok(pb::GetWalletLifecycleRecordResponse {
            record: MessageField::some(wallet_lifecycle_record_to_proto(&record)),
            ..Default::default()
        })
    }

    /// Standalone evidence append cannot preserve state/history atomicity.
    pub(crate) fn append_wallet_lifecycle_evidence(
        &mut self,
        _request: pb::AppendWalletLifecycleEvidenceRequest,
    ) -> RuntimeResult<pb::AppendWalletLifecycleEvidenceResponse> {
        Err(RuntimeError::new(RuntimeErrorReason::OperationUnsupported))
    }
}
