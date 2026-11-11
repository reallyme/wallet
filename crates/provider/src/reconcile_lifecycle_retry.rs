// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Require a bound provider reconciliation receipt before a failed retry.

use buffa::MessageField;
use reallyme_wallet_lifecycle::{
    is_wallet_lifecycle_retry, ReconciledWalletLifecycleRetry, WalletLifecycleEvent,
    WalletLifecycleEvidenceRecord, WalletLifecycleRecord,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    wallet_lifecycle_evidence_record_from_proto, wallet_lifecycle_evidence_record_to_proto,
    wallet_lifecycle_record_from_proto, wallet_lifecycle_record_to_proto,
};
use reallyme_wallet_runtime::RuntimeResult;
use reallyme_wallet_types::UnixTimestamp;

use crate::provider_backend::ProtobufProviderBackend;
use crate::provider_call_support::{provider_request, runtime_rejected};
use crate::{ProviderMethod, ProviderTransport};

const MAX_RECONCILIATION_CLOCK_ADVANCE_SECONDS: i64 = 60;

impl<T: ProviderTransport, M> ProtobufProviderBackend<T, M> {
    pub(crate) fn reconcile_lifecycle_retry(
        &mut self,
        current: &WalletLifecycleRecord,
        event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> RuntimeResult<ReconciledWalletLifecycleRetry> {
        let rejected = || runtime_rejected(ProviderMethod::VerifyLifecycleAuthority);
        if !is_wallet_lifecycle_retry(current, event) || evidence.event != event {
            return Err(rejected());
        }
        if let Some(verifier) = self.lifecycle_authority.as_ref() {
            return verifier
                .reconcile_wallet_lifecycle_retry(current, event, evidence, now)
                .map_err(|_| rejected());
        }
        let request = pb::VerifyLifecycleAuthorityProviderRequest {
            current: MessageField::some(wallet_lifecycle_record_to_proto(current)),
            evidence: MessageField::some(wallet_lifecycle_evidence_record_to_proto(evidence)),
            observed_at: MessageField::some(pb::UnixTimestamp {
                seconds: now.as_seconds(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = self
            .call(provider_request(request.into()))
            .map_err(|_| rejected())?;
        let pb::wallet_provider_result::Result::VerifyLifecycleAuthority(response) = result else {
            return Err(rejected());
        };
        let receipt = response
            .retry_reconciliation
            .as_option()
            .ok_or_else(rejected)?;
        let predecessor =
            wallet_lifecycle_record_from_proto(receipt.current.as_option().ok_or_else(rejected)?)
                .map_err(|_| rejected())?;
        let retry = wallet_lifecycle_evidence_record_from_proto(
            receipt.retry_evidence.as_option().ok_or_else(rejected)?,
        )
        .map_err(|_| rejected())?;
        let reconciled_at = UnixTimestamp::from_seconds(
            receipt
                .reconciled_at
                .as_option()
                .ok_or_else(rejected)?
                .seconds,
        )
        .map_err(|_| rejected())?;
        // Correlation of the RPC envelope is necessary but cannot substitute
        // for binding the receipt to the exact failed record and new evidence.
        let clock_advance = reconciled_at
            .as_seconds()
            .checked_sub(now.as_seconds())
            .ok_or_else(rejected)?;
        if predecessor != *current
            || retry != *evidence
            || !(0..=MAX_RECONCILIATION_CLOCK_ADVANCE_SECONDS).contains(&clock_advance)
        {
            return Err(rejected());
        }
        ReconciledWalletLifecycleRetry::new(predecessor, retry, reconciled_at)
            .map_err(|_| rejected())
    }
}
