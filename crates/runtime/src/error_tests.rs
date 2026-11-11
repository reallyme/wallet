// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    map_runtime_detail_reason, map_runtime_error_reason, wallet_error_envelope, RuntimeErrorReason,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

#[test]
fn unknown_negative_reason_does_not_alias_known_stack_reason() {
    let envelope = wallet_error_envelope(pb::WalletError {
        reason: (-306).into(),
        ..pb::WalletError::default()
    });
    assert!(matches!(envelope.stack.as_option(), Some(stack) if stack.reason_code == 0));
}

#[test]
fn known_reason_retains_its_stack_code() {
    let envelope = wallet_error_envelope(pb::WalletError {
        reason: pb::WalletErrorReason::WALLET_ERROR_REASON_ZK_PROVER_UNAVAILABLE.into(),
        ..pb::WalletError::default()
    });
    assert!(matches!(envelope.stack.as_option(), Some(stack) if stack.reason_code == 306));
}

#[test]
fn missing_record_keeps_exact_public_and_runtime_reasons() {
    assert_eq!(
        map_runtime_error_reason(RuntimeErrorReason::RecordNotFound),
        pb::WalletErrorReason::WALLET_ERROR_REASON_RECORD_NOT_FOUND
    );
    assert_eq!(
        map_runtime_detail_reason(RuntimeErrorReason::RecordNotFound),
        pb::RuntimeErrorReason::RUNTIME_ERROR_REASON_RECORD_NOT_FOUND
    );
}
