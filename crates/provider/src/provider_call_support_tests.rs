// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_runtime::RuntimeErrorReason;

use super::{map_provider_error, ProviderMethod};

#[test]
fn provider_not_found_retains_record_absence_for_read_methods() {
    let methods = [
        ProviderMethod::GetCredential,
        ProviderMethod::GetWalletLifecycle,
        ProviderMethod::GetFlowSnapshot,
        ProviderMethod::GetDidStorageRecord,
        ProviderMethod::GetPortableKeyStorageRecord,
        ProviderMethod::GetHardwareKeyBindingRecord,
    ];
    for method in methods {
        assert_eq!(
            map_provider_error(
                method,
                pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND
            )
            .reason,
            RuntimeErrorReason::RecordNotFound
        );
    }
}

#[test]
fn invalid_not_found_method_does_not_impersonate_a_missing_record() {
    assert_eq!(
        map_provider_error(
            ProviderMethod::AppendTransactionLog,
            pb::WalletProviderErrorReason::WALLET_PROVIDER_ERROR_REASON_NOT_FOUND
        )
        .reason,
        RuntimeErrorReason::LogStoreRejected
    );
}
