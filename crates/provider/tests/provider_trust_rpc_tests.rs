// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trusted time and lifecycle authority answered by the provider over the wire.
//!
//! These tests use a scripted provider that decodes every request, records
//! what it was asked, and answers `ReadTrustedTime` and
//! `VerifyLifecycleAuthority` the way a host provider would.

#![allow(clippy::field_reassign_with_default)]

use buffa::{EnumValue, MessageField};
use reallyme_wallet_lifecycle::{
    self as lifecycle, WalletLifecycleEvent, WalletLifecycleEvidenceKind,
    WalletLifecycleEvidenceRecord,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    wallet_lifecycle_evidence_record_to_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_proto_codec::decode::decode_wallet_provider_request;
use reallyme_wallet_proto_codec::encode::encode_wallet_provider_response;
use reallyme_wallet_provider::{
    build_provider_descriptor, ProviderContractError, ProviderExecutorId,
    ProviderHostCapabilityError, ProviderHostCapabilityErrorReason, ProviderInvocationMode,
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult, SynchronousProtobufProviderBackend, WalletLifecycleAuthorityVerifier,
};
use reallyme_wallet_runtime::{RuntimeErrorReason, WalletCoreRuntime, WalletRuntimeBackend};
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

/// How the scripted provider answers `ReadTrustedTime`.
#[derive(Clone, Copy)]
enum TimeAnswer {
    Seconds(i64),
    MissingTimestamp,
    ProviderError,
    WrongResult,
}

/// How the scripted provider answers `VerifyLifecycleAuthority`.
#[derive(Clone, Copy)]
enum AuthorityAnswer {
    Approve,
    Reject,
    WrongResult,
    Reconciled,
    ReconciledLater,
    InvalidReconciliation(u8),
}

/// What the provider saw in one `VerifyLifecycleAuthority` request.
struct AuthorityRequestSeen {
    current_state: Option<pb::WalletLifecycleState>,
    evidence_id: String,
    evidence_event: Option<pb::WalletLifecycleEvent>,
    observed_at: Option<i64>,
}

struct ScriptedProvider {
    time: TimeAnswer,
    authority: AuthorityAnswer,
    lifecycle: Option<pb::WalletLifecycleRecord>,
    lifecycle_revision: u64,
    authority_requests: Vec<AuthorityRequestSeen>,
    time_requests: usize,
    lifecycle_writes: usize,
    next_reservation: u64,
}

impl ScriptedProvider {
    fn new(time: TimeAnswer, authority: AuthorityAnswer) -> Self {
        Self {
            time,
            authority,
            lifecycle: None,
            lifecycle_revision: 1,
            authority_requests: Vec::new(),
            time_requests: 0,
            lifecycle_writes: 0,
            next_reservation: 0,
        }
    }

    fn answer(
        &mut self,
        request: &pb::WalletProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        use pb::wallet_provider_request::Request;
        match request.request.as_ref() {
            Some(Request::ReadTrustedTime(_)) => {
                self.time_requests = self.time_requests.saturating_add(1);
                self.read_trusted_time()
            }
            Some(Request::VerifyLifecycleAuthority(verify)) => {
                self.authority_requests.push(AuthorityRequestSeen {
                    current_state: verify
                        .current
                        .as_option()
                        .and_then(|record| record.state.as_known()),
                    evidence_id: verify
                        .evidence
                        .as_option()
                        .map(|evidence| evidence.id.clone())
                        .unwrap_or_default(),
                    evidence_event: verify
                        .evidence
                        .as_option()
                        .and_then(|evidence| evidence.event.as_known()),
                    observed_at: verify.observed_at.as_option().map(|time| time.seconds),
                });
                self.verify_authority(verify)
            }
            Some(Request::GetWalletLifecycle(get)) => self.get_lifecycle(get),
            Some(Request::CompareAndSwapWalletLifecycle(swap)) => self.swap_lifecycle(swap),
            Some(Request::BeginOperation(_)) => self.begin_operation(),
            Some(Request::CommitOperation(_)) => {
                success(pb::CommitOperationProviderResponse::default().into())
            }
            Some(_) | None => error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_UNSUPPORTED_CAPABILITY,
            ),
        }
    }

    fn read_trusted_time(&self) -> pb::wallet_provider_response::Outcome {
        match self.time {
            TimeAnswer::Seconds(seconds) => success(
                pb::ReadTrustedTimeProviderResponse {
                    observed_at: MessageField::some(pb::UnixTimestamp {
                        seconds,
                        ..Default::default()
                    }),
                    ..Default::default()
                }
                .into(),
            ),
            TimeAnswer::MissingTimestamp => {
                success(pb::ReadTrustedTimeProviderResponse::default().into())
            }
            TimeAnswer::ProviderError => {
                error(pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_UNAVAILABLE)
            }
            TimeAnswer::WrongResult => {
                success(pb::VerifyLifecycleAuthorityProviderResponse::default().into())
            }
        }
    }

    fn verify_authority(
        &self,
        request: &pb::VerifyLifecycleAuthorityProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        match self.authority {
            AuthorityAnswer::Reconciled
            | AuthorityAnswer::ReconciledLater
            | AuthorityAnswer::InvalidReconciliation(_) => {
                let mut receipt = pb::WalletLifecycleRetryReconciliation {
                    current: request.current.clone(),
                    retry_evidence: request.evidence.clone(),
                    reconciled_at: request.observed_at.clone(),
                    ..Default::default()
                };
                if let (AuthorityAnswer::ReconciledLater, Some(time)) =
                    (self.authority, receipt.reconciled_at.as_option_mut())
                {
                    time.seconds = time.seconds.saturating_add(1);
                }
                if let AuthorityAnswer::InvalidReconciliation(mode) = self.authority {
                    match mode {
                        0 => {
                            return success(
                                pb::VerifyLifecycleAuthorityProviderResponse::default().into(),
                            )
                        }
                        1 => {
                            if let Some(current) = receipt.current.as_option_mut() {
                                current.wallet_instance_id = "other-wallet".into();
                            }
                        }
                        2 => {
                            if let Some(evidence) = receipt.retry_evidence.as_option_mut() {
                                evidence.evidence_digest = vec![9; 32];
                            }
                        }
                        3 => {
                            if let Some(time) = receipt.reconciled_at.as_option_mut() {
                                time.seconds = 99;
                            }
                        }
                        4 => {
                            if let Some(current) = receipt.current.as_option_mut() {
                                current.resume_state = EnumValue::from(
                                    pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_SUSPENDED,
                                );
                            }
                        }
                        _ => receipt.current = MessageField::none(),
                    }
                }
                success(
                    pb::VerifyLifecycleAuthorityProviderResponse {
                        retry_reconciliation: MessageField::some(receipt),
                        ..Default::default()
                    }
                    .into(),
                )
            }
            AuthorityAnswer::Approve => {
                success(pb::VerifyLifecycleAuthorityProviderResponse::default().into())
            }
            AuthorityAnswer::Reject => {
                error(pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_REJECTED)
            }
            AuthorityAnswer::WrongResult => {
                success(pb::ReadTrustedTimeProviderResponse::default().into())
            }
        }
    }

    fn get_lifecycle(
        &self,
        request: &pb::GetWalletLifecycleProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        match self.lifecycle.as_ref() {
            Some(record) if record.wallet_instance_id == request.wallet_instance_id => success(
                pb::GetWalletLifecycleProviderResponse {
                    record: MessageField::some(record.clone()),
                    revision: MessageField::some(pb::RecordRevision {
                        value: self.lifecycle_revision,
                        ..Default::default()
                    }),
                    ..Default::default()
                }
                .into(),
            ),
            _ => error(pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND),
        }
    }

    fn swap_lifecycle(
        &mut self,
        request: &pb::CompareAndSwapWalletLifecycleProviderRequest,
    ) -> pb::wallet_provider_response::Outcome {
        let expected = request
            .expected_revision
            .as_option()
            .map(|value| value.value);
        let Some(record) = request.record.as_option() else {
            return error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_INVALID_REQUEST,
            );
        };
        if expected != Some(self.lifecycle_revision) {
            return error(
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_REVISION_CONFLICT,
            );
        }
        self.lifecycle_writes = self.lifecycle_writes.saturating_add(1);
        self.lifecycle_revision = self.lifecycle_revision.saturating_add(1);
        self.lifecycle = Some(record.clone());
        let mut response = pb::CompareAndSwapWalletLifecycleProviderResponse::default();
        response.wallet_instance_id = record.wallet_instance_id.clone();
        response.revision = MessageField::some(pb::RecordRevision {
            value: self.lifecycle_revision,
            ..Default::default()
        });
        success(response.into())
    }

    fn begin_operation(&mut self) -> pb::wallet_provider_response::Outcome {
        self.next_reservation = self.next_reservation.saturating_add(1);
        let mut begin = pb::BeginOperationProviderResponse::default();
        begin.outcome = Some(pb::begin_operation_provider_response::Outcome::Execute(
            Box::new(pb::OperationReservation {
                value: self.next_reservation,
                ..Default::default()
            }),
        ));
        success(begin.into())
    }
}

impl ProviderTransport for ScriptedProvider {
    fn invoke(
        &mut self,
        request_bytes: &[u8],
        max_response_bytes: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>> {
        let request = decode_wallet_provider_request(request_bytes).map_err(|_| rejected())?;
        let outcome = self.answer(&request);
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

/// An injected verifier that refuses everything.
struct DenyingVerifier;

impl WalletLifecycleAuthorityVerifier for DenyingVerifier {
    fn verify_wallet_lifecycle_authority(
        &self,
        _current: &lifecycle::WalletLifecycleRecord,
        _event: WalletLifecycleEvent,
        _evidence: &WalletLifecycleEvidenceRecord,
        _now: wallet::UnixTimestamp,
    ) -> Result<(), ProviderHostCapabilityError> {
        Err(ProviderHostCapabilityError::new(
            ProviderHostCapabilityErrorReason::Rejected,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("provider_contract")]
    ProviderContract(#[from] ProviderContractError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("lifecycle")]
    Lifecycle(#[from] lifecycle::LifecycleError),
    #[error("unexpected_result")]
    UnexpectedResult,
}

const ACTIVATED_AT: i64 = 100;
const SUSPENDED_AT: i64 = 110;

fn success(result: pb::wallet_provider_result::Result) -> pb::wallet_provider_response::Outcome {
    let mut provider_result = pb::WalletProviderResult::default();
    provider_result.result = Some(result);
    pb::wallet_provider_response::Outcome::Result(Box::new(provider_result))
}

fn error(reason: pb::WalletProviderErrorReason) -> pb::wallet_provider_response::Outcome {
    let mut provider_error = pb::WalletProviderError::default();
    provider_error.reason = EnumValue::from(reason);
    pb::wallet_provider_response::Outcome::Error(Box::new(provider_error))
}

fn rejected() -> ProviderTransportError {
    ProviderTransportError::new(ProviderTransportErrorReason::Rejected)
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn at(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

fn evidence(
    name: &str,
    event: WalletLifecycleEvent,
    kind: WalletLifecycleEvidenceKind,
    at_seconds: i64,
) -> Result<WalletLifecycleEvidenceRecord, TestError> {
    Ok(WalletLifecycleEvidenceRecord {
        id: id(name)?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind,
        event,
        occurred_at: at(at_seconds)?,
        authority_id: id("wallet-provider-1")?,
        evidence_ref: id("lifecycle-reference-1")?,
        evidence_digest: vec![1, 2, 3, 4],
    })
}

fn active_record() -> Result<lifecycle::WalletLifecycleRecord, TestError> {
    let record = lifecycle::new_wallet_lifecycle(id("wallet-unit-1")?, at(1)?);
    let begin = evidence(
        "evidence-begin",
        WalletLifecycleEvent::BeginProvisioning,
        WalletLifecycleEvidenceKind::Provisioning,
        2,
    )?;
    let record = lifecycle::apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        begin.occurred_at,
        Some(&begin),
    )?;
    let complete = evidence(
        "evidence-complete",
        WalletLifecycleEvent::CompleteProvisioning,
        WalletLifecycleEvidenceKind::Provisioning,
        ACTIVATED_AT,
    )?;
    Ok(lifecycle::apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::CompleteProvisioning,
        complete.occurred_at,
        Some(&complete),
    )?)
}

fn suspension() -> Result<WalletLifecycleEvidenceRecord, TestError> {
    evidence(
        "evidence-suspend",
        WalletLifecycleEvent::Suspend,
        WalletLifecycleEvidenceKind::Suspension,
        SUSPENDED_AT,
    )
}

fn backend(
    provider: ScriptedProvider,
) -> Result<SynchronousProtobufProviderBackend<ScriptedProvider>, TestError> {
    let descriptor = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    Ok(SynchronousProtobufProviderBackend::new_for_wallet(
        provider,
        &descriptor,
        ProviderExecutorId::new(93)?,
        id("wallet-unit-1")?,
    )?)
}

#[test]
fn provider_answered_time_is_used_when_no_clock_is_injected() -> Result<(), TestError> {
    let mut backend = backend(ScriptedProvider::new(
        TimeAnswer::Seconds(1_700_000_000),
        AuthorityAnswer::Reject,
    ))?;

    let now = backend
        .trusted_now()
        .map_err(|_| TestError::UnexpectedResult)?;

    assert_eq!(now.as_seconds(), 1_700_000_000);
    assert_eq!(backend.transport().time_requests, 1);
    Ok(())
}

#[test]
fn malformed_or_failed_provider_time_fails_closed() -> Result<(), TestError> {
    for answer in [
        TimeAnswer::MissingTimestamp,
        TimeAnswer::Seconds(i64::MAX),
        TimeAnswer::ProviderError,
        TimeAnswer::WrongResult,
    ] {
        let mut backend = backend(ScriptedProvider::new(answer, AuthorityAnswer::Reject))?;
        assert!(matches!(
            backend.trusted_now(),
            Err(error) if error.reason == RuntimeErrorReason::TrustedClockUnavailable
        ));
    }
    Ok(())
}

#[test]
fn provider_verifies_the_exact_predecessor_and_evidence() -> Result<(), TestError> {
    let mut backend = backend(ScriptedProvider::new(
        TimeAnswer::Seconds(SUSPENDED_AT),
        AuthorityAnswer::Approve,
    ))?;
    let current = active_record()?;
    let suspension = suspension()?;

    backend
        .verify_wallet_lifecycle_authority(
            &current,
            WalletLifecycleEvent::Suspend,
            &suspension,
            at(SUSPENDED_AT)?,
        )
        .map_err(|_| TestError::UnexpectedResult)?;

    let seen = backend
        .transport()
        .authority_requests
        .first()
        .ok_or(TestError::UnexpectedResult)?;
    assert_eq!(
        seen.current_state,
        Some(pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_ACTIVE)
    );
    assert_eq!(seen.evidence_id, "evidence-suspend");
    assert_eq!(
        seen.evidence_event,
        Some(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_SUSPEND)
    );
    assert_eq!(seen.observed_at, Some(SUSPENDED_AT));
    Ok(())
}

#[test]
fn rejected_or_malformed_provider_authority_denies_the_event() -> Result<(), TestError> {
    for answer in [AuthorityAnswer::Reject, AuthorityAnswer::WrongResult] {
        let mut backend = backend(ScriptedProvider::new(
            TimeAnswer::Seconds(SUSPENDED_AT),
            answer,
        ))?;
        let result = backend.verify_wallet_lifecycle_authority(
            &active_record()?,
            WalletLifecycleEvent::Suspend,
            &suspension()?,
            at(SUSPENDED_AT)?,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
        ));
    }
    Ok(())
}

#[test]
fn evidence_for_another_event_or_unit_never_reaches_the_provider() -> Result<(), TestError> {
    let mut backend = backend(ScriptedProvider::new(
        TimeAnswer::Seconds(SUSPENDED_AT),
        AuthorityAnswer::Approve,
    ))?;
    let current = active_record()?;
    let mut other_unit = suspension()?;
    other_unit.wallet_instance_id = id("wallet-unit-2")?;

    for (event, evidence) in [
        (WalletLifecycleEvent::Reactivate, suspension()?),
        (WalletLifecycleEvent::Suspend, other_unit),
    ] {
        assert!(matches!(
            backend.verify_wallet_lifecycle_authority(&current, event, &evidence, at(SUSPENDED_AT)?),
            Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
        ));
    }
    assert!(backend.transport().authority_requests.is_empty());
    Ok(())
}

#[test]
fn an_injected_verifier_replaces_the_provider_answer() -> Result<(), TestError> {
    let mut backend = backend(ScriptedProvider::new(
        TimeAnswer::Seconds(SUSPENDED_AT),
        AuthorityAnswer::Approve,
    ))?
    .with_lifecycle_authority_verifier(Box::new(DenyingVerifier));

    let result = backend.verify_wallet_lifecycle_authority(
        &active_record()?,
        WalletLifecycleEvent::Suspend,
        &suspension()?,
        at(SUSPENDED_AT)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::LifecyclePolicyDenied
    ));
    assert!(backend.transport().authority_requests.is_empty());
    Ok(())
}

fn suspend_request() -> Result<pb::WalletOperationRequest, TestError> {
    let mut apply = pb::ApplyWalletLifecycleEventRequest::default();
    apply.wallet_instance_id = "wallet-unit-1".to_owned();
    apply.event = EnumValue::from(pb::WalletLifecycleEvent::WALLET_LIFECYCLE_EVENT_SUSPEND);
    apply.evidence = MessageField::some(wallet_lifecycle_evidence_record_to_proto(&suspension()?));
    let mut request = pb::WalletOperationRequest::default();
    request.idempotency_key = vec![0x5A; 32];
    request.operation = apply.into();
    Ok(request)
}

fn runtime_with(
    authority: AuthorityAnswer,
) -> Result<WalletCoreRuntime<SynchronousProtobufProviderBackend<ScriptedProvider>>, TestError> {
    let mut provider = ScriptedProvider::new(TimeAnswer::Seconds(SUSPENDED_AT + 5), authority);
    provider.lifecycle = Some(wallet_lifecycle_record_to_proto(&active_record()?));
    Ok(WalletCoreRuntime::new(backend(provider)?))
}

fn stored_state(
    runtime: &WalletCoreRuntime<SynchronousProtobufProviderBackend<ScriptedProvider>>,
) -> Option<pb::WalletLifecycleState> {
    runtime
        .backend()
        .transport()
        .lifecycle
        .as_ref()
        .and_then(|record| record.state.as_known())
}

#[test]
fn a_lifecycle_event_commits_through_provider_time_and_authority() -> Result<(), TestError> {
    let mut runtime = runtime_with(AuthorityAnswer::Approve)?;

    let response = runtime.execute_operation(suspend_request()?);

    assert!(matches!(
        response.outcome,
        Some(pb::wallet_operation_response::Outcome::Result(_))
    ));
    assert_eq!(
        stored_state(&runtime),
        Some(pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_SUSPENDED)
    );
    assert_eq!(runtime.backend().transport().lifecycle_writes, 1);
    assert_eq!(runtime.backend().transport().authority_requests.len(), 1);
    assert!(runtime.backend().transport().time_requests >= 1);
    Ok(())
}

#[test]
fn a_provider_refusal_leaves_the_lifecycle_unchanged() -> Result<(), TestError> {
    let mut runtime = runtime_with(AuthorityAnswer::Reject)?;

    let response = runtime.execute_operation(suspend_request()?);

    assert!(matches!(
        response.outcome,
        Some(pb::wallet_operation_response::Outcome::Error(_))
    ));
    assert_eq!(
        stored_state(&runtime),
        Some(pb::WalletLifecycleState::WALLET_LIFECYCLE_STATE_ACTIVE)
    );
    assert_eq!(runtime.backend().transport().lifecycle_writes, 0);
    Ok(())
}

#[path = "provider_trust/retry_rpc.rs"]
mod retry_tests;
