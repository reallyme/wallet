// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host-injected authentication of lifecycle evidence authority.

use reallyme_wallet_lifecycle::{
    WalletLifecycleEvent, WalletLifecycleEvidenceRecord, WalletLifecycleRecord,
};
use reallyme_wallet_types::UnixTimestamp;

use crate::provider_call_support::{provider_request, runtime_rejected};
use crate::{ProviderHostCapabilityError, ProviderMethod};
use buffa::MessageField;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    wallet_lifecycle_evidence_record_to_proto, wallet_lifecycle_record_to_proto,
};

/// Verifier for authority-bearing Wallet Unit lifecycle evidence.
///
/// The runtime consults this verifier before committing an event for which
/// `reallyme_wallet_lifecycle::lifecycle_event_requires_verified_authority`
/// returns `true`. Operation requests are untrusted input, so the evidence
/// fields they carry prove nothing on their own. Implementations must
/// authenticate the referenced provider evidence, confirm that
/// `evidence_digest` matches it, and confirm that `authority_id` is trusted to
/// authorize `event` for the Wallet Unit in `current`. Anything else returns
/// an error and the transition is not committed. When no verifier is
/// attached, the backend asks the provider through `VerifyLifecycleAuthority`
/// instead, so the provider then carries this same obligation.
pub trait WalletLifecycleAuthorityVerifier: Send + Sync {
    /// Accept only evidence from an authority trusted for this exact event.
    fn verify_wallet_lifecycle_authority(
        &self,
        current: &WalletLifecycleRecord,
        event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> Result<(), ProviderHostCapabilityError>;

    /// Authenticate the new evidence and reconcile the exact failed operation.
    ///
    /// Successful ordinary authority verification alone cannot authorize retry.
    fn reconcile_wallet_lifecycle_retry(
        &self,
        _current: &WalletLifecycleRecord,
        _event: WalletLifecycleEvent,
        _evidence: &WalletLifecycleEvidenceRecord,
        _now: UnixTimestamp,
    ) -> Result<
        reallyme_wallet_lifecycle::ReconciledWalletLifecycleRetry,
        ProviderHostCapabilityError,
    > {
        Err(ProviderHostCapabilityError::new(
            crate::ProviderHostCapabilityErrorReason::Unavailable,
        ))
    }
}

impl<T: crate::ProviderTransport, M> crate::provider_backend::ProtobufProviderBackend<T, M> {
    pub(crate) fn verify_lifecycle_authority(
        &mut self,
        current: &WalletLifecycleRecord,
        event: WalletLifecycleEvent,
        evidence: &WalletLifecycleEvidenceRecord,
        now: UnixTimestamp,
    ) -> reallyme_wallet_runtime::RuntimeResult<()> {
        let rejected = || runtime_rejected(ProviderMethod::VerifyLifecycleAuthority);
        if evidence.event != event || &evidence.wallet_instance_id != current.wallet_instance_id() {
            return Err(rejected());
        }
        if let Some(verifier) = self.lifecycle_authority.as_ref() {
            return verifier
                .verify_wallet_lifecycle_authority(current, event, evidence, now)
                .map_err(|_| rejected());
        }
        let request = pb::VerifyLifecycleAuthorityProviderRequest {
            current: MessageField::some(wallet_lifecycle_record_to_proto(current)),
            evidence: MessageField::some(wallet_lifecycle_evidence_record_to_proto(evidence)),
            observed_at: MessageField::some(pb::UnixTimestamp {
                seconds: now.as_seconds(),
                ..Default::default()
            }),
            __buffa_unknown_fields: Default::default(),
        };
        match self
            .call(provider_request(request.into()))
            .map_err(|_| rejected())?
        {
            pb::wallet_provider_result::Result::VerifyLifecycleAuthority(response)
                if response.retry_reconciliation.as_option().is_none() =>
            {
                Ok(())
            }
            _ => Err(rejected()),
        }
    }
}
