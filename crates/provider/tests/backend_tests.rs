// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests for the synchronous protobuf provider backend.

#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;

use buffa::{EnumValue, MessageField};
use reallyme_wallet_lifecycle::{
    self as lifecycle, WalletLifecycleEvent, WalletLifecycleEvidenceKind,
    WalletLifecycleEvidenceRecord, WalletOperation,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    credential_record_to_proto, presentation_copy_to_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_proto_codec::decode::decode_wallet_provider_request;
use reallyme_wallet_proto_codec::encode::encode_wallet_provider_response;
use reallyme_wallet_provider::{
    build_provider_descriptor, ProviderContractError, ProviderExecutorId, ProviderInvocationMode,
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult, SynchronousProtobufProviderBackend,
};
use reallyme_wallet_runtime::{
    PresentationCopyClaimPolicy, RuntimeError, RuntimeErrorReason, WalletCoreRuntime,
    WalletRuntimeBackend,
};
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

enum JournalEntry {
    InProgress { digest: [u8; 32], reservation: u64 },
    Complete { digest: [u8; 32], response: Vec<u8> },
}

#[derive(Default)]
struct MemoryProviderTransport {
    journal: BTreeMap<[u8; 32], JournalEntry>,
    reservations: BTreeMap<u64, [u8; 32]>,
    credentials: BTreeMap<String, pb::CredentialRecord>,
    lifecycle: Option<pb::WalletLifecycleRecord>,
    next_reservation: u64,
    begin_count: usize,
    commit_count: usize,
    create_count: usize,
    lifecycle_read_count: usize,
    claim_policy: Option<pb::PresentationCopyClaimPolicy>,
    claim_copy_id: Option<String>,
    claim_copy: Option<pb::OnceOnlyPresentationCopy>,
}

impl ProviderTransport for MemoryProviderTransport {
    fn invoke(
        &mut self,
        request_bytes: &[u8],
        max_response_bytes: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>> {
        let request = decode_wallet_provider_request(request_bytes).map_err(|_| rejected())?;
        let outcome = match request.request.as_ref() {
            Some(pb::wallet_provider_request::Request::BeginOperation(begin)) => {
                self.begin_count = self.begin_count.saturating_add(1);
                self.begin_operation(begin)
            }
            Some(pb::wallet_provider_request::Request::CommitOperation(commit)) => {
                self.commit_count = self.commit_count.saturating_add(1);
                self.commit_operation(commit)
            }
            Some(pb::wallet_provider_request::Request::CreateCredential(create)) => {
                self.create_count = self.create_count.saturating_add(1);
                self.create_credential(create)
            }
            Some(pb::wallet_provider_request::Request::GetWalletLifecycle(get)) => {
                self.lifecycle_read_count = self.lifecycle_read_count.saturating_add(1);
                self.get_wallet_lifecycle(get)
            }
            Some(pb::wallet_provider_request::Request::ClaimPresentationCopy(claim)) => {
                self.claim_policy = claim.policy.as_known();
                self.claim_copy_id = Some(claim.copy_id.clone());
                match self.claim_copy.take() {
                    Some(copy) => provider_success(
                        pb::ClaimPresentationCopyProviderResponse {
                            copy: MessageField::some(copy),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    None => provider_error(
                        pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_UNSUPPORTED_CAPABILITY,
                    ),
                }
            }
            Some(_) => provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_UNSUPPORTED_CAPABILITY,
            ),
            None => provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_INVALID_REQUEST,
            ),
        };

        let mut response = pb::WalletProviderResponse::default();
        response.contract_version = request.contract_version;
        response.executor_id = request.executor_id;
        response.request_id = request.request_id;
        response.outcome = Some(outcome);
        let encoded = encode_wallet_provider_response(&response).map_err(|_| rejected())?;
        if encoded.len() > max_response_bytes {
            return Err(ProviderTransportError::new(
                ProviderTransportErrorReason::ResponseTooLarge,
            ));
        }
        Ok(encoded)
    }
}

impl MemoryProviderTransport {
    fn get_wallet_lifecycle(
        &self,
        request: &pb::GetWalletLifecycleProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        let Some(record) = self.lifecycle.as_ref() else {
            return provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND,
            );
        };
        if record.wallet_instance_id != request.wallet_instance_id {
            return provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND,
            );
        }
        provider_success(
            pb::GetWalletLifecycleProviderResponse {
                record: MessageField::some(record.clone()),
                revision: MessageField::some(pb::RecordRevision {
                    value: 1,
                    ..Default::default()
                }),
                ..Default::default()
            }
            .into(),
        )
    }

    fn begin_operation(
        &mut self,
        request: &pb::BeginOperationProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        let key = match <[u8; 32]>::try_from(request.idempotency_key.as_slice()) {
            Ok(value) if value.iter().any(|byte| *byte != 0) => value,
            Ok(_) | Err(_) => {
                return provider_error(
                    pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_INVALID_REQUEST,
                )
            }
        };
        let digest = match <[u8; 32]>::try_from(request.request_digest.as_slice()) {
            Ok(value) => value,
            Err(_) => {
                return provider_error(
                    pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_INVALID_REQUEST,
                )
            }
        };
        match self.journal.get(&key) {
            Some(JournalEntry::InProgress {
                digest: stored, ..
            }) if stored == &digest => provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_OPERATION_IN_PROGRESS,
            ),
            Some(JournalEntry::Complete {
                digest: stored,
                response,
            }) if stored == &digest => {
                let mut replay = pb::ReplayOperationResponse::default();
                replay.response = response.clone();
                let mut begin = pb::BeginOperationProviderResponse::default();
                begin.outcome = Some(pb::begin_operation_provider_response::Outcome::Replay(
                    Box::new(replay),
                ));
                provider_success(begin.into())
            }
            Some(_) => provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_IDEMPOTENCY_CONFLICT,
            ),
            None => {
                let reservation = match self.next_reservation.checked_add(1) {
                    Some(value) => value,
                    None => {
                        return provider_error(
                            pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_JOURNAL_REJECTED,
                        )
                    }
                };
                self.next_reservation = reservation;
                self.journal.insert(
                    key,
                    JournalEntry::InProgress {
                        digest,
                        reservation,
                    },
                );
                self.reservations.insert(reservation, key);
                let mut begin = pb::BeginOperationProviderResponse::default();
                begin.outcome = Some(pb::begin_operation_provider_response::Outcome::Execute(
                    Box::new(pb::OperationReservation {
                        value: reservation,
                        ..Default::default()
                    }),
                ));
                provider_success(begin.into())
            }
        }
    }

    fn commit_operation(
        &mut self,
        request: &pb::CommitOperationProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        let reservation = match request.reservation.as_option() {
            Some(value) if value.value != 0 => value.value,
            Some(_) | None => {
                return provider_error(
                    pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_INVALID_REQUEST,
                )
            }
        };
        let key =
            match self.reservations.remove(&reservation) {
                Some(value) => value,
                None => return provider_error(
                    pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_JOURNAL_REJECTED,
                ),
            };
        let digest =
            match self.journal.get(&key) {
                Some(JournalEntry::InProgress {
                    digest,
                    reservation: stored,
                }) if stored == &reservation => *digest,
                Some(_) | None => return provider_error(
                    pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_JOURNAL_REJECTED,
                ),
            };
        self.journal.insert(
            key,
            JournalEntry::Complete {
                digest,
                response: request.response.clone(),
            },
        );
        provider_success(pb::CommitOperationProviderResponse::default().into())
    }

    fn create_credential(
        &mut self,
        request: &pb::CreateCredentialProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        let record = match request.record.as_option() {
            Some(value) if !value.id.is_empty() => value,
            Some(_) | None => {
                return provider_error(
                    pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_INVALID_REQUEST,
                )
            }
        };
        if self.credentials.contains_key(&record.id) {
            return provider_error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_ALREADY_EXISTS,
            );
        }
        self.credentials.insert(record.id.clone(), record.clone());
        let mut response = pb::CreateCredentialProviderResponse::default();
        response.credential_id = record.id.clone();
        response.revision = MessageField::some(pb::RecordRevision {
            value: 1,
            ..Default::default()
        });
        provider_success(response.into())
    }
}

fn provider_success(
    result: pb::wallet_provider_result::Result,
) -> pb::wallet_provider_response::Outcome {
    let mut provider_result = pb::WalletProviderResult::default();
    provider_result.result = Some(result);
    pb::wallet_provider_response::Outcome::Result(Box::new(provider_result))
}

fn provider_error(reason: pb::WalletProviderErrorReason) -> pb::wallet_provider_response::Outcome {
    let mut error = pb::WalletProviderError::default();
    error.reason = EnumValue::from(reason);
    pb::wallet_provider_response::Outcome::Error(Box::new(error))
}

fn rejected() -> ProviderTransportError {
    ProviderTransportError::new(ProviderTransportErrorReason::Rejected)
}

fn backend(
) -> Result<SynchronousProtobufProviderBackend<MemoryProviderTransport>, ProviderContractError> {
    let descriptor = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    let executor_id = ProviderExecutorId::new(77)?;
    SynchronousProtobufProviderBackend::new(
        MemoryProviderTransport::default(),
        &descriptor,
        executor_id,
    )
}

fn put_request(
    key_byte: u8,
    credential_id: &str,
) -> Result<pb::WalletOperationRequest, wallet::WalletTypesError> {
    let mut record = credential_record()?;
    record.id = id(credential_id)?;
    let mut request = pb::WalletOperationRequest::default();
    request.idempotency_key = vec![key_byte; 32];
    request.operation = pb::PutCredentialRecordRequest {
        record: MessageField::some(credential_record_to_proto(&record)),
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

#[test]
fn unbound_provider_denies_regulated_operations_before_transport() -> Result<(), TestError> {
    let mut backend = backend()?;
    let result = backend.authorize_wallet_operation(WalletOperation::PresentCredential);

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::LifecycleStoreRejected
    ));
    assert_eq!(backend.transport().begin_count, 0);
    assert_eq!(backend.transport().commit_count, 0);
    assert_eq!(backend.transport().create_count, 0);
    assert_eq!(backend.transport().lifecycle_read_count, 0);
    Ok(())
}

#[test]
fn bound_provider_reloads_lifecycle_for_every_regulated_operation() -> Result<(), TestError> {
    let wallet_id = id("wallet-unit-1")?;
    let active = active_lifecycle()?;
    let transport = MemoryProviderTransport {
        lifecycle: Some(wallet_lifecycle_record_to_proto(&active)),
        ..Default::default()
    };
    let descriptor = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    let executor_id = ProviderExecutorId::new(78)?;
    let mut backend = SynchronousProtobufProviderBackend::new_for_wallet(
        transport,
        &descriptor,
        executor_id,
        wallet_id,
    )?;

    assert!(backend
        .authorize_wallet_operation(WalletOperation::PresentCredential)
        .is_ok());
    let suspended = advance_lifecycle(
        active,
        WalletLifecycleEvent::Suspend,
        WalletLifecycleEvidenceKind::Suspension,
        4,
    )?;
    backend.transport_mut().lifecycle = Some(wallet_lifecycle_record_to_proto(&suspended));
    assert!(matches!(
        backend.authorize_wallet_operation(WalletOperation::PresentCredential),
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert_eq!(backend.transport().lifecycle_read_count, 2);
    Ok(())
}

#[test]
fn prepared_claim_policy_reaches_the_storage_provider() -> Result<(), TestError> {
    let mut backend = backend()?;
    let credential_id = id("credential-1")?;
    assert!(backend
        .claim_presentation_copy(
            &credential_id,
            &id("copy-1")?,
            PresentationCopyClaimPolicy::ActiveZkCredential,
            None,
        )
        .is_err());
    assert!(backend
        .claim_presentation_copy(
            &credential_id,
            &id("copy-1")?,
            PresentationCopyClaimPolicy::ActiveZkCredential,
            Some(&[0; 32]),
        )
        .is_err());
    assert_eq!(backend.transport().claim_policy, None);
    assert!(backend
        .claim_presentation_copy(
            &credential_id,
            &id("copy-1")?,
            PresentationCopyClaimPolicy::ActiveZkCredential,
            Some(&[7; 32]),
        )
        .is_err());
    assert_eq!(
        backend.transport().claim_policy,
        Some(pb::PresentationCopyClaimPolicy::ActiveZkCredential)
    );
    assert_eq!(backend.transport().claim_copy_id.as_deref(), Some("copy-1"));
    Ok(())
}

#[test]
fn generic_claim_rejects_a_provider_returned_prepared_copy() -> Result<(), TestError> {
    let mut backend = backend()?;
    let copy = wallet::OnceOnlyPresentationCopy {
        id: id("copy-1")?,
        credential_id: id("credential-1")?,
        prepared_claim_selector_digest: Some([7; 32]),
        state: wallet::BatchCopyState::Claimed,
        encrypted_payload: wallet::EncryptedRecord {
            header: wallet::EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: wallet::KeyHandleId::new("key-provider".to_owned())?,
                algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
                created_at: timestamp()?,
            },
            nonce: vec![1; 12],
            aad: vec![2; 32],
            ciphertext: vec![3; 16],
        },
    };
    backend.transport_mut().claim_copy = Some(presentation_copy_to_proto(&copy));
    assert!(matches!(
        backend.claim_presentation_copy(
            &id("credential-1")?,
            &id("copy-1")?,
            PresentationCopyClaimPolicy::Generic,
            None,
        ),
        Err(error) if error.reason == RuntimeErrorReason::PresentationCopyStoreRejected
    ));
    assert_eq!(
        backend.transport().claim_policy,
        Some(pb::PresentationCopyClaimPolicy::Generic)
    );
    Ok(())
}

fn active_lifecycle() -> Result<lifecycle::WalletLifecycleRecord, TestError> {
    let record = lifecycle::new_wallet_lifecycle(id("wallet-unit-1")?, timestamp()?);
    let provisioning = advance_lifecycle(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        WalletLifecycleEvidenceKind::Provisioning,
        2,
    )?;
    advance_lifecycle(
        provisioning,
        WalletLifecycleEvent::CompleteProvisioning,
        WalletLifecycleEvidenceKind::Provisioning,
        3,
    )
}

fn advance_lifecycle(
    record: lifecycle::WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    kind: WalletLifecycleEvidenceKind,
    at_seconds: i64,
) -> Result<lifecycle::WalletLifecycleRecord, TestError> {
    let at = wallet::UnixTimestamp::from_seconds(at_seconds)?;
    let evidence = WalletLifecycleEvidenceRecord {
        id: id(&format!("lifecycle-evidence-{event:?}-{at_seconds}"))?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind,
        event,
        occurred_at: at,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("lifecycle-reference-1")?,
        evidence_digest: vec![1, 2, 3, 4],
    };
    Ok(lifecycle::apply_wallet_lifecycle_event(
        record,
        event,
        at,
        Some(&evidence),
    )?)
}

#[test]
fn forged_credential_receipt_replay_never_reaches_provider_create() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(backend()?);

    let first = runtime.execute_operation(put_request(0xA1, "credential-provider-1")?);
    let replay = runtime.execute_operation(put_request(0xA1, "credential-provider-1")?);

    assert_eq!(replay, first);
    assert!(response_has_runtime_reason(
        &first,
        pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID,
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED,
    ));
    // The disabled operation is refused before any journal reservation.
    let transport = runtime.backend().transport();
    assert_eq!(transport.begin_count, 0);
    assert_eq!(transport.create_count, 0);
    assert_eq!(transport.commit_count, 0);
    assert!(transport.credentials.is_empty());
    Ok(())
}

#[test]
fn provider_create_preserves_typed_already_exists_for_trusted_adapter() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(backend()?);
    runtime
        .backend_mut()
        .create_credential_record(credential_record()?)?;
    let duplicate = runtime
        .backend_mut()
        .create_credential_record(credential_record()?);

    assert!(matches!(
        duplicate,
        Err(error) if error.reason == RuntimeErrorReason::CredentialAlreadyExists
    ));
    assert_eq!(runtime.backend().transport().credentials.len(), 1);
    Ok(())
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp() -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(1)
}

fn credential_record() -> Result<wallet::CredentialRecord, wallet::WalletTypesError> {
    Ok(wallet::CredentialRecord::new(
        id("credential-provider")?,
        id("issuer-provider")?,
        None,
        None,
        None,
        wallet::CredentialFormat::SdJwtVc,
        wallet::CredentialStatus::Active,
        timestamp()?,
        wallet::EncryptedRecord {
            header: wallet::EncryptedRecordHeader {
                schema_version: 1,
                key_handle_id: wallet::KeyHandleId::new("key-provider".to_owned())?,
                algorithm: wallet::StorageEncryptionAlgorithm::Aes256GcmSiv,
                created_at: timestamp()?,
            },
            nonce: vec![1; 12],
            aad: vec![2],
            ciphertext: vec![3; 16],
        },
    ))
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("provider_contract")]
    ProviderContract(#[from] ProviderContractError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("runtime")]
    Runtime(#[from] RuntimeError),
    #[error("lifecycle")]
    Lifecycle(#[from] lifecycle::LifecycleError),
}
