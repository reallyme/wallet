// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Request-shape boundaries enforced before any durable state is touched.

use super::{
    active_backend, flow_snapshot, flow_snapshot_to_proto, mutating_operation_request, pb,
    response_has_runtime_reason, MessageField, RuntimeErrorReason, TestError, WalletCoreRuntime,
};

#[test]
fn disabled_operations_never_reserve_journal_entries() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let disabled: [pb::wallet_operation_request::Operation; 3] = [
        pb::PutCredentialRecordRequest::default().into(),
        pb::ApplyCredentialStatusEvidenceRequest::default().into(),
        pb::AppendWalletLifecycleEvidenceRequest::default().into(),
    ];
    for operation in disabled {
        let response = runtime.execute_operation(mutating_operation_request(operation));
        assert!(response_has_runtime_reason(
            &response,
            pb::WalletErrorReason::WALLET_ERROR_REASON_RUNTIME_REQUEST_INVALID,
            pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_OPERATION_UNSUPPORTED,
        ));
    }
    assert!(runtime.backend().journal.is_empty());
    Ok(())
}

#[test]
fn flow_snapshot_save_rejects_revision_zero() -> Result<(), TestError> {
    let mut runtime = WalletCoreRuntime::new(active_backend()?);
    let request = pb::SaveFlowSnapshotRequest {
        snapshot: MessageField::some(flow_snapshot_to_proto(&flow_snapshot()?)),
        expected_revision: MessageField::some(pb::RecordRevision {
            value: 0,
            ..pb::RecordRevision::default()
        }),
        ..pb::SaveFlowSnapshotRequest::default()
    };
    assert!(matches!(
        runtime.save_flow_snapshot(request),
        Err(error) if error.reason == RuntimeErrorReason::InvalidRequest
    ));
    assert!(runtime.backend().snapshots.is_empty());
    Ok(())
}
