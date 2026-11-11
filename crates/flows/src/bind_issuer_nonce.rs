// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bind authenticated nonce-provider observations to resumable issuance state.
use crate::{
    CredentialRequestProofBinding, FlowError, FlowErrorReason, FlowResult, IssuanceState,
    OpenId4VciIssuanceSession,
};
use reallyme_wallet_types::{IssuerNonceBinding, UnixTimestamp};
use zeroize::Zeroizing;
/// Conservative maximum age of a nonce observation before first submission.
pub const MAX_ISSUER_NONCE_AGE_SECONDS: i64 = 300;
const NONCE_SESSION_DOMAIN: &[u8] = b"reallyme.wallet.issuer-nonce-session.v1\0";
const MAX_NONCE_SESSION_TRANSCRIPT_BYTES: usize = 65_536;
fn rejected() -> FlowError {
    FlowError::new(FlowErrorReason::CredentialProofNonceBindingUnavailable)
}
fn append(bytes: &mut Vec<u8>, value: &[u8]) -> FlowResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| rejected())?;
    let end = bytes
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(value.len()))
        .ok_or_else(rejected)?;
    if end > MAX_NONCE_SESSION_TRANSCRIPT_BYTES {
        return Err(rejected());
    }
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}
/// Derive the binding expected from the authenticated nonce provider. Token
/// handles must be unique per issuance; the transport already owns that invariant.
pub fn issuer_nonce_session_digest(session: &OpenId4VciIssuanceSession) -> FlowResult<[u8; 32]> {
    let endpoint = session
        .issuer_metadata
        .nonce_endpoint
        .as_deref()
        .ok_or_else(rejected)?;
    let token = session
        .access_token_binding_handle
        .as_ref()
        .ok_or_else(rejected)?;
    let attestation = session
        .wallet_unit_attestation
        .as_ref()
        .ok_or_else(rejected)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(MAX_NONCE_SESSION_TRANSCRIPT_BYTES)
        .map_err(|_| rejected())?;
    for value in [
        NONCE_SESSION_DOMAIN,
        session.credential_issuer.as_bytes(),
        endpoint.as_bytes(),
        token.as_str().as_bytes(),
        attestation.evidence().key_handle_id.as_str().as_bytes(),
    ] {
        append(&mut bytes, value)?;
    }
    for configuration in &session.credential_configuration_ids {
        append(&mut bytes, configuration.as_bytes())?;
    }
    Ok(crypto_sha2_256::digest(&bytes).into_bytes())
}
/// Bind the observation returned by the host's authenticated nonce provider.
/// The provider owns HTTPS/issuer authentication and exact nonce bytes; Wallet
/// owns session identity, freshness, immutable retries and proof comparison.
pub fn bind_openid4vci_issuer_nonce(
    session: &mut OpenId4VciIssuanceSession,
    binding: IssuerNonceBinding,
    now: UnixTimestamp,
) -> FlowResult<()> {
    if session.state != IssuanceState::TokenExchanged
        || session.credential_request.is_some()
        || binding.session_digest != issuer_nonce_session_digest(session)?
        || binding.nonce_digest == [0; 32]
        || binding.received_at > now
        || now >= binding.expires_at
        || binding.expires_at <= binding.received_at
        || binding
            .received_at
            .as_seconds()
            .checked_add(MAX_ISSUER_NONCE_AGE_SECONDS)
            .is_none_or(|limit| binding.expires_at.as_seconds() > limit)
    {
        return Err(rejected());
    }
    if let Some(existing) = &session.issuer_nonce_binding {
        if existing != &binding {
            return Err(rejected());
        }
        return Ok(());
    }
    session.issuer_nonce_binding = Some(binding);
    Ok(())
}
pub(crate) fn validate_nonce_binding(
    session: &OpenId4VciIssuanceSession,
    binding: &CredentialRequestProofBinding,
    now: Option<UnixTimestamp>,
) -> FlowResult<()> {
    let Some(nonce) = session.issuer_nonce_binding.as_ref() else {
        return if session.issuer_metadata.nonce_endpoint.is_some() {
            Err(rejected())
        } else {
            Ok(())
        };
    };
    if nonce.nonce_digest == [0; 32]
        || nonce.session_digest != issuer_nonce_session_digest(session)?
        || nonce.expires_at <= nonce.received_at
        || nonce
            .received_at
            .as_seconds()
            .checked_add(MAX_ISSUER_NONCE_AGE_SECONDS)
            .is_none_or(|limit| nonce.expires_at.as_seconds() > limit)
        || now.is_some_and(|time| time < nonce.received_at || time >= nonce.expires_at)
        || binding.proofs.iter().any(|proof| {
            proof.nonce_digest != Some(nonce.nonce_digest)
                || proof.issued_at < nonce.received_at
                || proof.issued_at >= nonce.expires_at
        })
    {
        return Err(rejected());
    }
    Ok(())
}
