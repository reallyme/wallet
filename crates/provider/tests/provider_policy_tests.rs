// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Negative and happy-path tests for provider descriptor and exchange policy.

// Hardened generated provider owners implement Drop and cannot use struct
// update syntax without moving their hidden unknown-field owner.
#![allow(clippy::field_reassign_with_default)]

use buffa::EnumValue;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_provider::{
    build_provider_descriptor, validate_provider_descriptor, validate_provider_exchange,
    ProviderContractError, ProviderContractErrorReason, ProviderExecutorId, ProviderInvocationMode,
    ProviderRequestSequence, ValidatedProviderOutcome,
};

#[test]
fn complete_native_descriptor_is_accepted() -> Result<(), ProviderContractError> {
    let descriptor = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);

    let validated =
        validate_provider_descriptor(&descriptor, ProviderInvocationMode::SynchronousNative)?;

    assert!(validated.invocation_mode() == ProviderInvocationMode::SynchronousNative);
    assert_eq!(
        validated.max_response_bytes(),
        reallyme_wallet_proto_codec::MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES
    );
    Ok(())
}

#[test]
fn descriptor_rejects_missing_duplicate_unknown_and_wrong_mode() {
    let mut missing = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    missing.capabilities.pop();
    assert!(matches!(
        validate_provider_descriptor(&missing, ProviderInvocationMode::SynchronousNative),
        Err(error) if error.reason == ProviderContractErrorReason::CapabilityMissing
    ));

    let mut duplicate = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    if let Some(first) = duplicate.capabilities.first().copied() {
        duplicate.capabilities.push(first);
    }
    assert!(matches!(
        validate_provider_descriptor(&duplicate, ProviderInvocationMode::SynchronousNative),
        Err(error) if error.reason == ProviderContractErrorReason::CapabilityDuplicate
    ));

    let mut unknown = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    unknown.capabilities[0] = EnumValue::from(99_999_i32);
    assert!(matches!(
        validate_provider_descriptor(&unknown, ProviderInvocationMode::SynchronousNative),
        Err(error) if error.reason == ProviderContractErrorReason::CapabilityUnknown
    ));

    let asynchronous = build_provider_descriptor(ProviderInvocationMode::AsynchronousHost);
    assert!(matches!(
        validate_provider_descriptor(
            &asynchronous,
            ProviderInvocationMode::SynchronousNative
        ),
        Err(error) if error.reason == ProviderContractErrorReason::InvocationModeMismatch
    ));
}

#[test]
fn descriptor_rejects_version_and_response_limit_drift() {
    let mut version = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    version.contract_version = 2;
    assert!(matches!(
        validate_provider_descriptor(&version, ProviderInvocationMode::SynchronousNative),
        Err(error) if error.reason == ProviderContractErrorReason::UnsupportedContractVersion
    ));

    let mut limit = build_provider_descriptor(ProviderInvocationMode::SynchronousNative);
    limit.max_response_bytes = limit.max_response_bytes.saturating_sub(1);
    assert!(matches!(
        validate_provider_descriptor(&limit, ProviderInvocationMode::SynchronousNative),
        Err(error) if error.reason == ProviderContractErrorReason::ResponseLimitInvalid
    ));
}

#[test]
fn provider_exchange_requires_exact_correlation_and_result_pairing(
) -> Result<(), ProviderContractError> {
    let executor_id = ProviderExecutorId::new(41)?;
    let mut sequence = ProviderRequestSequence::new(executor_id);
    let mut request = pb::WalletProviderRequest::default();
    request.request = pb::GetCredentialProviderRequest::default().into();
    sequence.assign(&mut request)?;

    let mut result = pb::WalletProviderResult::default();
    result.result = pb::GetCredentialProviderResponse::default().into();
    let mut response = pb::WalletProviderResponse::default();
    response.contract_version = request.contract_version;
    response.executor_id = request.executor_id;
    response.request_id = request.request_id;
    response.outcome = Some(pb::wallet_provider_response::Outcome::Result(Box::new(
        result,
    )));
    assert!(validate_provider_exchange(&request, &response)? == ValidatedProviderOutcome::Success);

    response.request_id = response.request_id.saturating_add(1);
    assert!(matches!(
        validate_provider_exchange(&request, &response),
        Err(error) if error.reason == ProviderContractErrorReason::ResponseRequestMismatch
    ));
    response.request_id = request.request_id;

    let mut mismatched = pb::WalletProviderResult::default();
    mismatched.result = pb::GetFlowSnapshotProviderResponse::default().into();
    response.outcome = Some(pb::wallet_provider_response::Outcome::Result(Box::new(
        mismatched,
    )));
    assert!(matches!(
        validate_provider_exchange(&request, &response),
        Err(error) if error.reason == ProviderContractErrorReason::ResponseResultMismatch
    ));
    Ok(())
}

#[test]
fn provider_exchange_accepts_only_known_nonzero_error_reasons() -> Result<(), ProviderContractError>
{
    let executor_id = ProviderExecutorId::new(42)?;
    let mut sequence = ProviderRequestSequence::new(executor_id);
    let mut request = pb::WalletProviderRequest::default();
    request.request = pb::CreateCredentialProviderRequest::default().into();
    sequence.assign(&mut request)?;

    let mut error = pb::WalletProviderError::default();
    error.reason =
        EnumValue::from(pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_ALREADY_EXISTS);
    let mut response = pb::WalletProviderResponse::default();
    response.contract_version = request.contract_version;
    response.executor_id = request.executor_id;
    response.request_id = request.request_id;
    response.outcome = Some(pb::wallet_provider_response::Outcome::Error(Box::new(
        error,
    )));
    assert!(matches!(
        validate_provider_exchange(&request, &response)?,
        ValidatedProviderOutcome::Error(
            pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_ALREADY_EXISTS
        )
    ));

    let mut unspecified = pb::WalletProviderError::default();
    unspecified.reason =
        EnumValue::from(pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_UNSPECIFIED);
    response.outcome = Some(pb::wallet_provider_response::Outcome::Error(Box::new(
        unspecified,
    )));
    assert!(matches!(
        validate_provider_exchange(&request, &response),
        Err(error) if error.reason == ProviderContractErrorReason::ResponseErrorUnknown
    ));
    Ok(())
}

#[test]
fn did_and_key_storage_operations_require_exact_provider_results(
) -> Result<(), ProviderContractError> {
    use pb::wallet_provider_request::Request;
    use pb::wallet_provider_result::Result as ProviderResult;

    let exchanges = vec![
        (
            Request::from(pb::SaveDidStorageRecordProviderRequest::default()),
            ProviderResult::from(pb::SaveDidStorageRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::GetDidStorageRecordProviderRequest::default()),
            ProviderResult::from(pb::GetDidStorageRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::DeleteDidStorageRecordProviderRequest::default()),
            ProviderResult::from(pb::DeleteDidStorageRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::SavePortableKeyStorageRecordProviderRequest::default()),
            ProviderResult::from(pb::SavePortableKeyStorageRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::GetPortableKeyStorageRecordProviderRequest::default()),
            ProviderResult::from(pb::GetPortableKeyStorageRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::DeletePortableKeyStorageRecordProviderRequest::default()),
            ProviderResult::from(pb::DeletePortableKeyStorageRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::SaveHardwareKeyBindingRecordProviderRequest::default()),
            ProviderResult::from(pb::SaveHardwareKeyBindingRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::GetHardwareKeyBindingRecordProviderRequest::default()),
            ProviderResult::from(pb::GetHardwareKeyBindingRecordProviderResponse::default()),
        ),
        (
            Request::from(pb::DeleteHardwareKeyBindingRecordProviderRequest::default()),
            ProviderResult::from(pb::DeleteHardwareKeyBindingRecordProviderResponse::default()),
        ),
    ];
    let executor_id = ProviderExecutorId::new(43)?;
    let mut sequence = ProviderRequestSequence::new(executor_id);

    for (request_variant, result_variant) in exchanges {
        let mut request = pb::WalletProviderRequest::default();
        request.request = Some(request_variant);
        sequence.assign(&mut request)?;

        let mut result = pb::WalletProviderResult::default();
        result.result = Some(result_variant);
        let mut response = pb::WalletProviderResponse::default();
        response.contract_version = request.contract_version;
        response.executor_id = request.executor_id;
        response.request_id = request.request_id;
        response.outcome = Some(pb::wallet_provider_response::Outcome::Result(Box::new(
            result,
        )));

        assert!(
            validate_provider_exchange(&request, &response)? == ValidatedProviderOutcome::Success
        );

        let mut substituted = pb::WalletProviderResult::default();
        substituted.result = pb::GetCredentialProviderResponse::default().into();
        response.outcome = Some(pb::wallet_provider_response::Outcome::Result(Box::new(
            substituted,
        )));
        assert!(matches!(
            validate_provider_exchange(&request, &response),
            Err(error) if error.reason == ProviderContractErrorReason::ResponseResultMismatch
        ));
    }
    Ok(())
}
