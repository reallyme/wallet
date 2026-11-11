// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execute the canonical transport-neutral Wallet operation union.

use reallyme_wallet_lifecycle::WalletOperation;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    flow_snapshot_from_proto, transaction_log_entry_from_proto,
};
use reallyme_wallet_proto_codec::decode::{
    decode_wallet_operation_request, decode_wallet_operation_response,
};
use reallyme_wallet_proto_codec::encode::{
    encode_wallet_operation_request, encode_wallet_operation_response,
};
use reallyme_wallet_proto_codec::ProtoResult;
use reallyme_wallet_types::{FlowKind, NonEmptyIdentifier};
use zeroize::Zeroizing;

use crate::authorize_audit_record::transaction_history_operation;
use crate::encode_operation_replay::{
    claimed_copy_id, decode_replay_record, encode_once_only_replay_record, encode_replay_record,
    ReplayRecord,
};
use crate::validate_replay::replay_answers_operation;
use crate::{
    runtime_error_envelope, OperationIdempotencyKey, OperationReplayDecision,
    OperationRequestDigest, RuntimeError, RuntimeErrorReason, WalletCoreRuntime,
    WalletRuntimeBackend,
};

/// Type-erased operation seam consumed by the owning SDK repository.
///
/// The trait deliberately exposes only the versioned protobuf byte contract.
/// Identity adapters can own a concrete executor behind an opaque handle
/// without learning the backend type or duplicating the operation catalog.
/// Those adapters remain responsible for explicit provider construction and
/// their foreign-boundary concurrency, reentrancy, and memory policy.
pub trait WalletOperationExecutor {
    /// Execute one canonical version-1 Wallet operation protobuf message.
    fn execute_wallet_operation_v1(
        &mut self,
        request_bytes: &[u8],
    ) -> ProtoResult<Zeroizing<Vec<u8>>>;
}

impl<B> WalletCoreRuntime<B>
where
    B: WalletRuntimeBackend,
{
    /// Execute one decoded Wallet operation and return its canonical outcome.
    ///
    /// Missing variants, domain validation failures, and injected-backend
    /// failures are expected operation outcomes and are represented in the
    /// response envelope. Protobuf framing and decoding failures remain the
    /// responsibility of the calling adapter because no request exists until
    /// decoding has succeeded.
    #[must_use]
    pub fn execute_operation(
        &mut self,
        mut request: pb::WalletOperationRequest,
    ) -> pb::WalletOperationResponse {
        let Some(operation) = request.operation.as_ref() else {
            return operation_response(Err(RuntimeError::new(RuntimeErrorReason::InvalidRequest)));
        };
        // Disabled operations can never succeed. Refuse them before any key
        // check or journal entry so fresh keys cannot grow durable replay state.
        if operation_is_disabled(operation) {
            return operation_response(Err(RuntimeError::new(
                RuntimeErrorReason::OperationUnsupported,
            )));
        }

        // Journal entries outlive executor handles. Check the bound unit even
        // for a replay, before a cached lifecycle response can be released.
        if let Err(error) = self.require_operation_wallet_binding(operation) {
            return operation_response(Err(error));
        }

        // A replay is still a regulated wallet operation. Check the live state
        // before consulting the journal so a cached success cannot bypass a
        // later suspension, withdrawal, or deletion.
        let lifecycle_operation = match regulated_operation(operation) {
            Ok(operation) => operation,
            Err(error) => return operation_response(Err(error)),
        };
        if let Some(operation) = lifecycle_operation {
            if let Err(error) = self.backend_mut().authorize_wallet_operation(operation) {
                return operation_response(Err(error));
            }
        }

        if !operation_is_mutating(operation) {
            if !request.idempotency_key.is_empty() {
                return operation_response(Err(RuntimeError::new(
                    RuntimeErrorReason::IdempotencyKeyInvalid,
                )));
            }
            let result = request
                .operation
                .take()
                .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
                .and_then(|operation| self.dispatch_operation(operation));
            return operation_response(result);
        }

        if request.idempotency_key.is_empty() {
            return operation_response(Err(RuntimeError::new(
                RuntimeErrorReason::IdempotencyKeyMissing,
            )));
        }
        let idempotency_key = match OperationIdempotencyKey::from_slice(&request.idempotency_key) {
            Ok(key) => key,
            Err(_) => {
                return operation_response(Err(RuntimeError::new(
                    RuntimeErrorReason::IdempotencyKeyInvalid,
                )));
            }
        };
        if let Some(pb::wallet_operation_request::Operation::ApplyWalletLifecycleEvent(
            lifecycle_request,
        )) = request.operation.as_mut()
        {
            // The legacy caller time is ignored by the handler. Excluding it from
            // the digest lets equivalent transitions replay the same response.
            lifecycle_request.now = Default::default();
        }
        let encoded_request = match encode_wallet_operation_request(&request) {
            Ok(encoded) => encoded,
            Err(_) => {
                return operation_response(Err(RuntimeError::new(
                    RuntimeErrorReason::InvalidRequest,
                )));
            }
        };
        let request_digest = OperationRequestDigest::new(
            crypto_sha2_256::digest(encoded_request.as_slice()).into_bytes(),
        );

        let reservation = match self
            .backend_mut()
            .begin_idempotent_operation(&idempotency_key, &request_digest)
        {
            Ok(OperationReplayDecision::Execute(reservation)) => reservation,
            Ok(OperationReplayDecision::Replay(response)) => {
                let Some(operation) = request.operation.as_ref() else {
                    return operation_response(Err(RuntimeError::new(
                        RuntimeErrorReason::InvalidRequest,
                    )));
                };
                return match decode_replay_record(response.as_slice(), &request_digest) {
                    Ok(ReplayRecord::Response(encoded)) => {
                        match decode_wallet_operation_response(encoded) {
                            // The journal is provider storage. Release only a
                            // response that answers this exact operation, and
                            // never a successful once-only claim with its copy.
                            Ok(response) if replay_answers_operation(operation, &response) => {
                                response
                            }
                            Ok(_) | Err(_) => operation_response(Err(RuntimeError::new(
                                RuntimeErrorReason::IdempotencyStoreRejected,
                            ))),
                        }
                    }
                    Ok(ReplayRecord::OnceOnlyClaim)
                        if matches!(
                            operation,
                            pb::wallet_operation_request::Operation::ClaimPresentationCopy(_)
                        ) =>
                    {
                        operation_response(Err(RuntimeError::new(
                            RuntimeErrorReason::PresentationCopyAlreadyClaimed,
                        )))
                    }
                    Ok(ReplayRecord::OnceOnlyClaim) => operation_response(Err(RuntimeError::new(
                        RuntimeErrorReason::IdempotencyStoreRejected,
                    ))),
                    Err(_) => operation_response(Err(RuntimeError::new(
                        RuntimeErrorReason::IdempotencyStoreRejected,
                    ))),
                };
            }
            Err(error) => return operation_response(Err(error)),
        };

        let once_only_claim = matches!(
            request.operation.as_ref(),
            Some(pb::wallet_operation_request::Operation::ClaimPresentationCopy(_))
        );
        let result = request
            .operation
            .take()
            .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))
            .and_then(|operation| self.dispatch_operation(operation));
        let response = operation_response(result);
        let (response, encoded_response, encoded_original) =
            match encode_wallet_operation_response(&response) {
                Ok(encoded) => (response, encoded, true),
                Err(_) => {
                    // The mutation has already happened. Commit a small terminal
                    // error so a retry cannot leave this key reserved forever.
                    core::mem::drop(response);
                    let terminal = operation_response(Err(RuntimeError::new(
                        RuntimeErrorReason::OperationResponseTooLarge,
                    )));
                    match encode_wallet_operation_response(&terminal) {
                        Ok(encoded) => (terminal, encoded, false),
                        Err(_) => {
                            return operation_response(Err(RuntimeError::new(
                                RuntimeErrorReason::IdempotencyStoreRejected,
                            )));
                        }
                    }
                }
            };
        let replay_record_result = if once_only_claim && encoded_original {
            match claimed_copy_id(&response) {
                Some(copy_id) => encode_once_only_replay_record(&request_digest, copy_id),
                None => encode_replay_record(&request_digest, encoded_response.as_slice()),
            }
        } else {
            encode_replay_record(&request_digest, encoded_response.as_slice())
        };
        let replay_record = match replay_record_result {
            Ok(record) => record,
            Err(error) => return operation_response(Err(error)),
        };
        const COMMIT_ATTEMPTS: usize = 3;
        let mut committed = false;
        for _attempt in 0..COMMIT_ATTEMPTS {
            if self
                .backend_mut()
                .commit_idempotent_operation(&reservation, replay_record.as_slice())
                .is_ok()
            {
                committed = true;
                break;
            }
        }
        if !committed {
            return operation_response(Err(RuntimeError::new(
                RuntimeErrorReason::IdempotencyStoreRejected,
            )));
        }

        response
    }

    /// Execute one canonical version-1 Wallet operation protobuf message.
    ///
    /// The input slice remains caller-owned and should be wiped by an adapter
    /// when it contains privacy-bearing material. The returned buffer owns and
    /// zeroizes the encoded response. Framing, size, recursion, and unknown
    /// field failures are returned as typed codec errors; decoded domain and
    /// backend failures are encoded in `WalletOperationResponse.error`.
    pub fn execute_wallet_operation_v1(
        &mut self,
        request_bytes: &[u8],
    ) -> ProtoResult<Zeroizing<Vec<u8>>> {
        let request = decode_wallet_operation_request(request_bytes)?;
        let response = self.execute_operation(request);
        encode_wallet_operation_response(&response)
    }

    fn require_operation_wallet_binding(
        &self,
        operation: &pb::wallet_operation_request::Operation,
    ) -> Result<(), RuntimeError> {
        use pb::wallet_operation_request::Operation;

        let requested_id = match operation {
            Operation::PutWalletLifecycleRecord(request) => request
                .record
                .as_option()
                .map(|record| record.wallet_instance_id.as_str())
                .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))?,
            Operation::GetWalletLifecycleRecord(request) => &request.wallet_instance_id,
            Operation::ApplyWalletLifecycleEvent(request) => &request.wallet_instance_id,
            _ => return Ok(()),
        };
        let requested_id = NonEmptyIdentifier::new(requested_id.to_owned())
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
        self.require_bound_wallet(&requested_id)
    }

    fn dispatch_operation(
        &mut self,
        operation: pb::wallet_operation_request::Operation,
    ) -> Result<pb::wallet_operation_result::Result, RuntimeError> {
        use pb::wallet_operation_request::Operation;

        match operation {
            Operation::PutWalletLifecycleRecord(request) => self
                .put_wallet_lifecycle_record(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::GetWalletLifecycleRecord(request) => self
                .get_wallet_lifecycle_record(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::ApplyWalletLifecycleEvent(request) => self
                .apply_wallet_lifecycle_event(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::AppendWalletLifecycleEvidence(request) => self
                .append_wallet_lifecycle_evidence(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::PutCredentialRecord(request) => self
                .put_credential_record(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::GetCredentialRecord(request) => self
                .get_credential_record(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::ApplyCredentialStatusEvidence(request) => self
                .apply_credential_status_evidence(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::DeleteCredentialRecord(request) => self
                .delete_credential_record(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::ClaimPresentationCopy(request) => self
                .claim_presentation_copy(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::EvaluateVerifierEntitlement(request) => self
                .evaluate_verifier_entitlement(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::SaveFlowSnapshot(request) => self
                .save_flow_snapshot(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::GetFlowSnapshot(request) => self
                .get_flow_snapshot(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::AppendTransactionLog(request) => self
                .append_transaction_log(*request)
                .map(pb::wallet_operation_result::Result::from),
            Operation::AppendQtspDecision(request) => self
                .append_qtsp_decision(*request)
                .map(pb::wallet_operation_result::Result::from),
        }
    }
}

fn operation_is_mutating(operation: &pb::wallet_operation_request::Operation) -> bool {
    use pb::wallet_operation_request::Operation;

    matches!(
        operation,
        Operation::PutWalletLifecycleRecord(_)
            | Operation::ApplyWalletLifecycleEvent(_)
            | Operation::AppendWalletLifecycleEvidence(_)
            | Operation::PutCredentialRecord(_)
            | Operation::ApplyCredentialStatusEvidence(_)
            | Operation::DeleteCredentialRecord(_)
            | Operation::ClaimPresentationCopy(_)
            | Operation::SaveFlowSnapshot(_)
            | Operation::AppendTransactionLog(_)
            | Operation::AppendQtspDecision(_)
    )
}

/// Operations kept in the v1 wire contract that the runtime always rejects
/// because a protobuf request cannot carry the verifier capability they need.
fn operation_is_disabled(operation: &pb::wallet_operation_request::Operation) -> bool {
    use pb::wallet_operation_request::Operation;

    matches!(
        operation,
        Operation::PutCredentialRecord(_)
            | Operation::ApplyCredentialStatusEvidence(_)
            | Operation::EvaluateVerifierEntitlement(_)
            | Operation::AppendWalletLifecycleEvidence(_)
    )
}

fn regulated_operation(
    operation: &pb::wallet_operation_request::Operation,
) -> Result<Option<WalletOperation>, RuntimeError> {
    use pb::wallet_operation_request::Operation;

    match operation {
        Operation::GetCredentialRecord(_) | Operation::GetFlowSnapshot(_) => {
            Ok(Some(WalletOperation::ReadWalletRecords))
        }
        Operation::DeleteCredentialRecord(_) => Ok(Some(WalletOperation::DeleteWallet)),
        Operation::ClaimPresentationCopy(_) => Ok(Some(WalletOperation::PresentCredential)),
        Operation::AppendQtspDecision(_) => Ok(Some(WalletOperation::SignWithWalletKey)),
        Operation::AppendTransactionLog(request) => {
            let entry = request
                .entry
                .as_option()
                .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
            let entry = transaction_log_entry_from_proto(entry).map_err(RuntimeError::from)?;
            Ok(Some(transaction_history_operation(entry.purpose)))
        }
        Operation::SaveFlowSnapshot(request) => {
            let snapshot = request
                .snapshot
                .as_option()
                .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidRequest))?;
            let snapshot = flow_snapshot_from_proto(snapshot).map_err(RuntimeError::from)?;
            Ok(Some(match snapshot.kind {
                FlowKind::Issuance => WalletOperation::BeginIssuance,
                FlowKind::Presentation => WalletOperation::PresentCredential,
            }))
        }
        _ => Ok(None),
    }
}

fn operation_response(
    result: Result<pb::wallet_operation_result::Result, RuntimeError>,
) -> pb::WalletOperationResponse {
    match result {
        Ok(result) => pb::WalletOperationResponse {
            outcome: pb::wallet_operation_response::Outcome::Result(Box::new(
                pb::WalletOperationResult {
                    result: Some(result),
                    ..Default::default()
                },
            ))
            .into(),
            ..Default::default()
        },
        Err(error) => pb::WalletOperationResponse {
            outcome: pb::wallet_operation_response::Outcome::Error(Box::new(
                runtime_error_envelope(error.reason),
            ))
            .into(),
            ..Default::default()
        },
    }
}

impl<B> WalletOperationExecutor for WalletCoreRuntime<B>
where
    B: WalletRuntimeBackend,
{
    fn execute_wallet_operation_v1(
        &mut self,
        request_bytes: &[u8],
    ) -> ProtoResult<Zeroizing<Vec<u8>>> {
        WalletCoreRuntime::execute_wallet_operation_v1(self, request_bytes)
    }
}
