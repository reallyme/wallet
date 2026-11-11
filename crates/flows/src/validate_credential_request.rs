// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate authenticated bindings from an OpenID4VCI credential request.

use std::collections::BTreeSet;

use openid4vci_types::{CredentialRequest, Proofs};
use reallyme_wallet_types::UnixTimestamp;

use crate::credential_request_proof::CredentialRequestProofBinding;
use crate::import_issued_credentials::MAX_ISSUED_CREDENTIALS_PER_RESPONSE;
use crate::issue::OpenId4VciIssuanceSession;
use crate::{FlowError, FlowErrorReason, FlowResult};

const MAX_CREDENTIAL_PROOF_AGE_SECONDS: i64 = 300;
const MAX_CREDENTIAL_PROOF_FUTURE_SKEW_SECONDS: i64 = 60;

pub(crate) fn validate_proof_binding(
    session: &OpenId4VciIssuanceSession,
    request: &CredentialRequest,
    binding: &CredentialRequestProofBinding,
    now: UnixTimestamp,
) -> FlowResult<()> {
    crate::bind_issuer_nonce::validate_nonce_binding(session, binding, Some(now))?;
    let minimum_issued_at = now
        .as_seconds()
        .checked_sub(MAX_CREDENTIAL_PROOF_AGE_SECONDS)
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let maximum_issued_at = now
        .as_seconds()
        .checked_add(MAX_CREDENTIAL_PROOF_FUTURE_SKEW_SECONDS)
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let expected_key = session
        .wallet_unit_attestation
        .as_ref()
        .map(|attestation| &attestation.evidence().key_handle_id)
        .ok_or_else(|| FlowError::new(FlowErrorReason::WalletUnitAttestationRequired))?;
    let proof_shape_matches = request
        .proofs
        .as_ref()
        .is_some_and(|proofs| proof_shape_matches_binding(proofs, binding.proofs.len()));
    if !proof_shape_matches
        || binding.proofs.is_empty()
        || &binding.wallet_unit_key_handle_id != expected_key
    {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    let mut unique_handles = BTreeSet::new();
    for proof in &binding.proofs {
        if proof.audience != session.credential_issuer
            || proof.issued_at.as_seconds() < minimum_issued_at
            || proof.issued_at.as_seconds() > maximum_issued_at
            // Holder proofs and wallet-unit attestation serve different
            // purposes; sharing a key links otherwise independent uses.
            || &proof.holder_key_handle_id == expected_key
            || !unique_handles.insert(&proof.holder_key_handle_id)
        {
            return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
        }
    }
    Ok(())
}

pub(crate) fn proof_shape_matches_binding(proofs: &Proofs, binding_count: usize) -> bool {
    if binding_count == 0 || binding_count > MAX_ISSUED_CREDENTIALS_PER_RESPONSE {
        return false;
    }
    match (
        proofs.jwt.is_empty(),
        proofs.di_vp.is_empty(),
        proofs.attestation.is_empty(),
    ) {
        (false, true, true) => proofs.jwt.len() == binding_count,
        (true, false, true) => proofs.di_vp.len() == binding_count,
        // One signed key attestation may authenticate several distinct
        // credential-binding keys for a batch request.
        (true, true, false) => proofs.attestation.len() == 1 && binding_count > 0,
        _ => false,
    }
}
