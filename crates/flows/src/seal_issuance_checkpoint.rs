// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticate restored issuance stages and their exact session coordinates.

use crypto_core::MacAlgorithm;
use crypto_hmac::{authenticate, verify, HmacKey};
use openid4vci_types::CredentialOffer;
use reallyme_codec::jcs::canonicalize_json_text;
use reallyme_openid4vci_wallet::CredentialOfferGrantType;
use reallyme_wallet_types::{CredentialReuseMethod, OpenId4VciIssuerMetadataProfile};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceState, OpenId4VciIssuanceSession};

const CHECKPOINT_DOMAIN: &[u8] = b"reallyme.wallet.openid4vci.checkpoint.v1\0";
const MAX_FIELD_BYTES: usize = 4_194_304;
const MAX_TRANSCRIPT_BYTES: usize = 65_536;
const TAG_BYTES: usize = 32;

/// Installation-local key for authenticating stored issuance checkpoints.
pub struct IssuanceCheckpointKey(HmacKey);

impl IssuanceCheckpointKey {
    /// Use a persistent, randomly generated key isolated to this Wallet Unit.
    pub fn new(secret: SecretBox<[u8; TAG_BYTES]>) -> FlowResult<Self> {
        if secret.expose_secret().iter().all(|byte| *byte == 0) {
            return Err(invalid());
        }
        HmacKey::from_slice(secret.expose_secret())
            .map(Self)
            .map_err(|_| invalid())
    }

    /// Authenticate the live state before persisting it with its snapshot.
    ///
    /// Persist the tag with the snapshot in authenticated, revisioned storage.
    /// The tag does not encrypt the snapshot or supply rollback protection.
    pub fn seal(
        &self,
        session: &OpenId4VciIssuanceSession,
    ) -> FlowResult<Zeroizing<[u8; TAG_BYTES]>> {
        let transcript = transcript(session)?;
        let tag =
            authenticate(MacAlgorithm::HmacSha256, &self.0, &transcript).map_err(|_| invalid())?;
        let bytes = tag.as_bytes().try_into().map_err(|_| invalid())?;
        Ok(Zeroizing::new(bytes))
    }
}

/// Authenticator for a stored stage read from the owning Wallet Unit.
pub struct IssuanceResumeProof<'a> {
    key: &'a IssuanceCheckpointKey,
    tag: &'a [u8; TAG_BYTES],
}

impl<'a> IssuanceResumeProof<'a> {
    /// Pair a persisted tag with the owning unit's installation-local key.
    pub const fn new(key: &'a IssuanceCheckpointKey, tag: &'a [u8; TAG_BYTES]) -> Self {
        Self { key, tag }
    }

    pub(crate) fn verify(&self, session: &OpenId4VciIssuanceSession) -> FlowResult<()> {
        let transcript = transcript(session)?;
        verify(MacAlgorithm::HmacSha256, &self.key.0, &transcript, self.tag).map_err(|_| invalid())
    }
}

pub(crate) fn offer_digest(offer: &CredentialOffer) -> FlowResult<Zeroizing<[u8; TAG_BYTES]>> {
    let json = Zeroizing::new(offer.to_json().map_err(|_| invalid())?);
    canonical_json_digest(&json)
}

fn canonical_json_digest(json: &str) -> FlowResult<Zeroizing<[u8; TAG_BYTES]>> {
    if json.len() > MAX_FIELD_BYTES {
        return Err(invalid());
    }
    let canonical = Zeroizing::new(canonicalize_json_text(json).map_err(|_| invalid())?);
    Ok(Zeroizing::new(
        crypto_sha2_256::digest(canonical.as_bytes()).into_bytes(),
    ))
}

fn append(buffer: &mut Vec<u8>, value: &[u8]) -> FlowResult<()> {
    if value.len() > MAX_FIELD_BYTES
        || buffer
            .len()
            .checked_add(TAG_BYTES)
            .is_none_or(|len| len > MAX_TRANSCRIPT_BYTES)
    {
        return Err(invalid());
    }
    // Each transcript field has a fixed-width digest, including absent values.
    buffer.extend_from_slice(crypto_sha2_256::digest(value).as_bytes());
    Ok(())
}

fn optional_json(buffer: &mut Vec<u8>, value: Option<Zeroizing<String>>) -> FlowResult<()> {
    match value {
        Some(json) => append(buffer, canonical_json_digest(&json)?.as_ref()),
        None => append(buffer, &[]),
    }
}

fn append_policy(buffer: &mut Vec<u8>, session: &OpenId4VciIssuanceSession) -> FlowResult<()> {
    let count = u32::try_from(session.credential_reuse_policies.len()).map_err(|_| invalid())?;
    append(buffer, &count.to_be_bytes())?;
    for policy in &session.credential_reuse_policies {
        append(
            buffer,
            policy.credential_configuration_id().as_str().as_bytes(),
        )?;
        append(
            buffer,
            &[match policy.method() {
                CredentialReuseMethod::Unrestricted => 1,
                CredentialReuseMethod::OnceOnly => 2,
                CredentialReuseMethod::LimitedTime => 3,
                CredentialReuseMethod::RotatingBatch => 4,
                CredentialReuseMethod::PerRelyingParty => 5,
            }],
        )?;
        append(
            buffer,
            policy
                .batch_size()
                .map(u32::to_be_bytes)
                .as_ref()
                .map_or(&[], |v| &v[..]),
        )?;
        append(
            buffer,
            policy
                .reissue_trigger_unused()
                .map(u32::to_be_bytes)
                .as_ref()
                .map_or(&[], |v| &v[..]),
        )?;
        append(
            buffer,
            policy
                .reissue_trigger_lifetime_left_seconds()
                .map(u64::to_be_bytes)
                .as_ref()
                .map_or(&[], |v| &v[..]),
        )?;
    }
    Ok(())
}

fn append_attestation(buffer: &mut Vec<u8>, session: &OpenId4VciIssuanceSession) -> FlowResult<()> {
    let Some(attestation) = session.wallet_unit_attestation.as_ref() else {
        return append(buffer, &[0]);
    };
    append(buffer, &[1])?;
    let evidence = attestation.evidence();
    for field in [
        attestation.id().as_str().as_bytes(),
        attestation.signed_provider_artifact(),
        attestation.verified_key_thumbprint().as_bytes(),
        &attestation.valid_until().as_seconds().to_be_bytes(),
        evidence.key_handle_id.as_str().as_bytes(),
        evidence.evidence.as_slice(),
        &evidence.issued_at.as_seconds().to_be_bytes(),
        &evidence.challenge,
    ] {
        append(buffer, field)?;
    }
    Ok(())
}

fn transcript(session: &OpenId4VciIssuanceSession) -> FlowResult<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(MAX_TRANSCRIPT_BYTES)
        .map_err(|_| invalid())?;
    append(&mut buffer, CHECKPOINT_DOMAIN)?;
    append(&mut buffer, session.offer_digest.as_ref())?;
    let metadata = Zeroizing::new(session.issuer_metadata.to_json().map_err(|_| invalid())?);
    append(&mut buffer, canonical_json_digest(&metadata)?.as_ref())?;
    append(
        &mut buffer,
        session.issuance.authorization_server().as_bytes(),
    )?;
    append(
        &mut buffer,
        &[
            match session.grant_type {
                CredentialOfferGrantType::AuthorizationCode => 1,
                CredentialOfferGrantType::PreAuthorizedCode => 2,
            },
            match session.issuer_metadata_profile {
                OpenId4VciIssuerMetadataProfile::OpenId4Vci => 1,
                OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3 => 2,
                OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3 => 3,
            },
            match &session.state {
                IssuanceState::OfferReceived => 1,
                IssuanceState::ConsentCaptured => 2,
                IssuanceState::Authorized => 3,
                IssuanceState::TokenExchanged => 4,
                IssuanceState::Deferred => 5,
                IssuanceState::CredentialReceived => 6,
                IssuanceState::CredentialStored { .. } => 7,
            },
        ],
    )?;
    if let IssuanceState::CredentialStored { credential_ids } = &session.state {
        let count = u32::try_from(credential_ids.len()).map_err(|_| invalid())?;
        append(&mut buffer, &count.to_be_bytes())?;
        for id in credential_ids {
            append(&mut buffer, id.as_str().as_bytes())?;
        }
    }
    append_policy(&mut buffer, session)?;
    append(
        &mut buffer,
        session
            .access_token_binding_handle
            .as_ref()
            .map_or(&[], |id| id.as_str().as_bytes()),
    )?;
    append_attestation(&mut buffer, session)?;
    if let Some(nonce) = session.issuer_nonce_binding.as_ref() {
        append(&mut buffer, &[1])?;
        append(&mut buffer, &nonce.session_digest)?;
        append(&mut buffer, &nonce.nonce_digest)?;
        append(&mut buffer, &nonce.received_at.as_seconds().to_be_bytes())?;
        append(&mut buffer, &nonce.expires_at.as_seconds().to_be_bytes())?;
    } else {
        append(&mut buffer, &[0])?;
    }
    let count =
        u32::try_from(session.credential_binding_key_handle_ids.len()).map_err(|_| invalid())?;
    append(&mut buffer, &count.to_be_bytes())?;
    for key in &session.credential_binding_key_handle_ids {
        append(&mut buffer, key.as_str().as_bytes())?;
    }
    optional_json(
        &mut buffer,
        session
            .credential_request
            .as_ref()
            .map(|request| request.to_json().map(Zeroizing::new).map_err(|_| invalid()))
            .transpose()?,
    )?;
    optional_json(
        &mut buffer,
        session
            .credential_response
            .as_ref()
            .map(|response| {
                response
                    .to_json()
                    .map(Zeroizing::new)
                    .map_err(|_| invalid())
            })
            .transpose()?,
    )?;
    if let Some(deferred) = session.deferred_issuance.as_ref() {
        append(&mut buffer, deferred.transaction_id.as_str().as_bytes())?;
        append(&mut buffer, &deferred.interval_seconds.to_be_bytes())?;
    } else {
        append(&mut buffer, &[])?;
    }
    Ok(buffer)
}

fn invalid() -> FlowError {
    FlowError::new(FlowErrorReason::InvalidOpenId4VciState)
}
