// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host-injected trusted time and lifecycle authority for the provider backend.

use reallyme_wallet_lifecycle::{
    self as lifecycle, WalletLifecycleEvent, WalletLifecycleEvidenceKind,
    WalletLifecycleEvidenceRecord,
};
use reallyme_wallet_provider::{
    build_provider_descriptor, ProviderContractError, ProviderExecutorId,
    ProviderHostCapabilityError, ProviderHostCapabilityErrorReason, ProviderInvocationMode,
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult, ProviderTrustedClock, SynchronousProtobufProviderBackend,
    WalletLifecycleAuthorityVerifier,
};
use reallyme_wallet_runtime::{RuntimeError, RuntimeErrorReason, WalletRuntimeBackend};
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

struct UnreachableTransport;

impl ProviderTransport for UnreachableTransport {
    fn invoke(
        &mut self,
        _request: &[u8],
        _max_response_bytes: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>> {
        Err(ProviderTransportError::new(
            ProviderTransportErrorReason::Unavailable,
        ))
    }
}

struct FixedClock(Option<i64>);

impl ProviderTrustedClock for FixedClock {
    fn trusted_now(&self) -> Result<wallet::UnixTimestamp, ProviderHostCapabilityError> {
        let seconds = self.0.ok_or(ProviderHostCapabilityError::new(
            ProviderHostCapabilityErrorReason::Unavailable,
        ))?;
        wallet::UnixTimestamp::from_seconds(seconds).map_err(|_| {
            ProviderHostCapabilityError::new(ProviderHostCapabilityErrorReason::Unavailable)
        })
    }
}

struct TrustedAuthority(&'static str);

impl WalletLifecycleAuthorityVerifier for TrustedAuthority {
    fn verify_wallet_lifecycle_authority(
        &self,
        _current: &lifecycle::WalletLifecycleRecord,
        _event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        _now: wallet::UnixTimestamp,
    ) -> Result<(), ProviderHostCapabilityError> {
        if evidence.authority_id.as_str() == self.0 {
            Ok(())
        } else {
            Err(ProviderHostCapabilityError::new(
                ProviderHostCapabilityErrorReason::Rejected,
            ))
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("provider_contract")]
    ProviderContract(#[from] ProviderContractError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
    #[error("unexpected_result")]
    UnexpectedResult,
}

fn backend() -> Result<SynchronousProtobufProviderBackend<UnreachableTransport>, TestError> {
    let descriptor = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    Ok(SynchronousProtobufProviderBackend::new(
        UnreachableTransport,
        &descriptor,
        ProviderExecutorId::new(91)?,
    )?)
}

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn provisioning_record() -> Result<lifecycle::WalletLifecycleRecord, TestError> {
    let record = lifecycle::new_wallet_lifecycle(
        id("wallet-unit-1")?,
        wallet::UnixTimestamp::from_seconds(1)?,
    );
    let evidence = evidence(
        "wallet-provider-1",
        WalletLifecycleEvent::BeginProvisioning,
        2,
    )?;
    lifecycle::apply_wallet_lifecycle_event(
        record,
        WalletLifecycleEvent::BeginProvisioning,
        evidence.occurred_at,
        Some(&evidence),
    )
    .map_err(|_| TestError::UnexpectedResult)
}

fn evidence(
    authority: &str,
    event: WalletLifecycleEvent,
    at_seconds: i64,
) -> Result<WalletLifecycleEvidenceRecord, TestError> {
    Ok(WalletLifecycleEvidenceRecord {
        id: id("lifecycle-evidence-1")?,
        wallet_instance_id: id("wallet-unit-1")?,
        kind: WalletLifecycleEvidenceKind::Provisioning,
        event,
        occurred_at: wallet::UnixTimestamp::from_seconds(at_seconds)?,
        authority_id: id(authority)?,
        evidence_ref: id("lifecycle-evidence-reference-1")?,
        evidence_digest: vec![1, 2, 3, 4],
    })
}

fn is_reason(result: Result<(), RuntimeError>, reason: RuntimeErrorReason) -> bool {
    matches!(result, Err(error) if error.reason == reason)
}

#[test]
fn provider_backend_fails_closed_when_no_clock_and_no_provider_answer() -> Result<(), TestError> {
    let mut backend = backend()?;
    assert!(matches!(
        backend.trusted_now(),
        Err(error) if error.reason == RuntimeErrorReason::TrustedClockUnavailable
    ));
    Ok(())
}

#[test]
fn provider_backend_reads_only_the_injected_clock() -> Result<(), TestError> {
    let mut backend = backend()?.with_trusted_clock(Box::new(FixedClock(Some(1_700_000_000))));
    let now = backend
        .trusted_now()
        .map_err(|_| TestError::UnexpectedResult)?;
    assert_eq!(now.as_seconds(), 1_700_000_000);

    let mut failing = backend.with_trusted_clock(Box::new(FixedClock(None)));
    assert!(matches!(
        failing.trusted_now(),
        Err(error) if error.reason == RuntimeErrorReason::TrustedClockUnavailable
    ));
    Ok(())
}

#[test]
fn provider_backend_denies_authority_when_no_verifier_and_no_provider_answer(
) -> Result<(), TestError> {
    let mut backend = backend()?;
    let current = provisioning_record()?;
    let evidence = evidence(
        "wallet-provider-1",
        WalletLifecycleEvent::CompleteProvisioning,
        3,
    )?;
    assert!(is_reason(
        backend.verify_wallet_lifecycle_authority(
            &current,
            WalletLifecycleEvent::CompleteProvisioning,
            &evidence,
            wallet::UnixTimestamp::from_seconds(3)?,
        ),
        RuntimeErrorReason::LifecyclePolicyDenied,
    ));
    Ok(())
}

#[test]
fn provider_backend_delegates_authority_to_the_injected_verifier() -> Result<(), TestError> {
    let mut backend = backend()?
        .with_lifecycle_authority_verifier(Box::new(TrustedAuthority("wallet-provider-1")));
    let current = provisioning_record()?;
    let now = wallet::UnixTimestamp::from_seconds(3)?;

    let trusted = evidence(
        "wallet-provider-1",
        WalletLifecycleEvent::CompleteProvisioning,
        3,
    )?;
    backend
        .verify_wallet_lifecycle_authority(
            &current,
            WalletLifecycleEvent::CompleteProvisioning,
            &trusted,
            now,
        )
        .map_err(|_| TestError::UnexpectedResult)?;

    let forged = evidence(
        "self-asserted-caller",
        WalletLifecycleEvent::CompleteProvisioning,
        3,
    )?;
    assert!(is_reason(
        backend.verify_wallet_lifecycle_authority(
            &current,
            WalletLifecycleEvent::CompleteProvisioning,
            &forged,
            now,
        ),
        RuntimeErrorReason::LifecyclePolicyDenied,
    ));
    Ok(())
}
