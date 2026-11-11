// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use super::{ProviderExecutorId, ProviderRequestSequence};
use crate::ProviderContractErrorReason;

#[test]
fn rejects_zero_executor_identifier() {
    assert!(matches!(
        ProviderExecutorId::new(0),
        Err(error) if error.reason == ProviderContractErrorReason::ExecutorIdInvalid
    ));
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn assigns_nonzero_checked_correlation_fields() -> Result<(), crate::ProviderContractError> {
    let executor_id = ProviderExecutorId::new(7)?;
    let mut sequence = ProviderRequestSequence::new(executor_id);
    let mut request = pb::WalletProviderRequest::default();
    request.request = pb::BeginOperationProviderRequest::default().into();

    sequence.assign(&mut request)?;

    assert_eq!(request.contract_version, 1);
    assert_eq!(request.executor_id, 7);
    assert_eq!(request.request_id, 1);
    Ok(())
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn fails_closed_after_request_identifier_exhaustion() -> Result<(), crate::ProviderContractError> {
    let executor_id = ProviderExecutorId::new(7)?;
    let mut sequence = ProviderRequestSequence {
        executor_id,
        next_request_id: u64::MAX,
    };
    let mut final_request = pb::WalletProviderRequest::default();
    final_request.request = pb::BeginOperationProviderRequest::default().into();
    sequence.assign(&mut final_request)?;
    assert_eq!(final_request.request_id, u64::MAX);

    let mut exhausted = pb::WalletProviderRequest::default();
    exhausted.request = pb::BeginOperationProviderRequest::default().into();
    assert!(matches!(
        sequence.assign(&mut exhausted),
        Err(error) if error.reason == ProviderContractErrorReason::RequestIdExhausted
    ));
    Ok(())
}
