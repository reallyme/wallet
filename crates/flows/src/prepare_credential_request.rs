// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prepare metadata-bound OpenID4VCI credential requests.

use buffa::{DecodeOptions, Message};
use openid4vci_profiles::validate_etsi_credential_request_proofs;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as vci_pb;
use openid4vci_types::{CredentialFormat, IssuerMetadata};
use openid4vci_types::{
    CredentialRequest, CredentialResponseEncryption, Proofs, ReallyMeZkV1IssuanceRequest,
};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_openid4vci_wallet::WalletCredentialRequest;
use reallyme_wallet_types::OpenId4VciIssuerMetadataProfile;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::issue::OpenId4VciIssuanceSession;
use crate::{FlowError, FlowErrorReason, FlowResult};

const ZK_ISSUANCE_VERSION: u32 = 1;
const ZK_DIGEST_BYTES: usize = 32;
const P256_UNCOMPRESSED_BYTES: usize = 65;
const P256_UNCOMPRESSED_PREFIX: u8 = 0x04;
const ZK_ISSUANCE_RECURSION_LIMIT: u32 = 8;

/// Credential request prepared against the session's metadata-bound issuance.
///
/// The OpenID4VCI crate deliberately keeps its transport request opaque so a
/// caller cannot bypass an encryption commitment. Wallet retains the canonical
/// request separately for proof verification and resumable state, while only
/// exposing the opaque request to the injected transport boundary.
pub struct PreparedOpenId4VciCredentialRequest {
    pub(crate) issuer_nonce_binding: Option<reallyme_wallet_types::IssuerNonceBinding>,
    pub(crate) canonical_request: CredentialRequest,
    pub(crate) transport_request: WalletCredentialRequest,
    /// Retain the exact validated metadata used by the request builder. A
    /// second session can authorize the same configuration with a different
    /// request-encryption policy, so issuer and configuration alone are not a
    /// sufficient binding.
    pub(crate) issuer_metadata: Arc<IssuerMetadata>,
}

impl PreparedOpenId4VciCredentialRequest {
    /// Borrow the opaque request for a transport adapter.
    ///
    /// The returned type exposes only policy-enforcing serialization and
    /// encryption operations; it does not expose the canonical inner request.
    #[must_use]
    pub const fn transport_request(&self) -> &WalletCredentialRequest {
        &self.transport_request
    }

    /// Borrow the optional DPoP proof for transport-level assertions.
    #[must_use]
    pub fn dpop_proof_jwt(&self) -> Option<&str> {
        self.transport_request.dpop_proof_jwt()
    }
}

/// Build a credential request bound to the session's validated issuance.
pub fn prepare_openid4vci_credential_request(
    session: &OpenId4VciIssuanceSession,
    credential_configuration_id: String,
    proofs: Option<Proofs>,
    credential_response_encryption: Option<CredentialResponseEncryption>,
    dpop_proof_jwt: Option<String>,
) -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    prepare_credential_request(
        session,
        credential_configuration_id,
        proofs,
        credential_response_encryption,
        dpop_proof_jwt,
        None,
    )
}

/// Build a ZK credential request from a wallet-prepared protobuf issuance intent.
///
/// The caller retains the private openings corresponding to the public root in
/// the intent and must reconcile them with the verified issuer receipt.
pub fn prepare_openid4vci_zk_credential_request(
    session: &OpenId4VciIssuanceSession,
    credential_configuration_id: String,
    proofs: Option<Proofs>,
    credential_response_encryption: Option<CredentialResponseEncryption>,
    dpop_proof_jwt: Option<String>,
    issuance: ReallyMeZkV1IssuanceRequest,
) -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    validate_zk_issuance_intent(&issuance)?;
    prepare_credential_request(
        session,
        credential_configuration_id,
        proofs,
        credential_response_encryption,
        dpop_proof_jwt,
        Some(issuance),
    )
}

fn validate_zk_issuance_intent(issuance: &ReallyMeZkV1IssuanceRequest) -> FlowResult<()> {
    let bytes = Zeroizing::new(
        base64url_to_bytes(issuance.compact())
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
    );
    if bytes.is_empty()
        || bytes.len() > openid4vci_types::MAX_REALLYME_ZK_V1_ISSUANCE_REQUEST_BYTES
        || bytes_to_base64url(&bytes) != issuance.compact()
    {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    let mut wire = DecodeOptions::new()
        .with_recursion_limit(ZK_ISSUANCE_RECURSION_LIMIT)
        .with_max_message_size(openid4vci_types::MAX_REALLYME_ZK_V1_ISSUANCE_REQUEST_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<vci_pb::ReallyMeZkV1IssuanceRequest>(&bytes)
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    let valid = wire.encode_to_vec().as_slice() == bytes.as_slice()
        && wire.version == ZK_ISSUANCE_VERSION
        && wire.claims_root.len() == ZK_DIGEST_BYTES
        && wire.claims_root.iter().any(|byte| *byte != 0)
        && wire.verified_holder_public_key.len() == P256_UNCOMPRESSED_BYTES
        && wire.verified_holder_public_key.first() == Some(&P256_UNCOMPRESSED_PREFIX)
        && wire.lineage_tag_commitment.len() == ZK_DIGEST_BYTES
        && wire.lineage_tag_commitment.iter().any(|byte| *byte != 0)
        && wire.wallet_opening_commitment.len() == ZK_DIGEST_BYTES
        && wire.wallet_opening_commitment.iter().any(|byte| *byte != 0)
        && wire.opaque_lineage_leaf.len() == ZK_DIGEST_BYTES
        && wire.opaque_lineage_leaf.iter().any(|byte| *byte != 0);
    wire.claims_root.fill(0);
    wire.verified_holder_public_key.fill(0);
    wire.lineage_tag_commitment.fill(0);
    wire.wallet_opening_commitment.fill(0);
    wire.opaque_lineage_leaf.fill(0);
    if !valid {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    Ok(())
}

fn prepare_credential_request(
    session: &OpenId4VciIssuanceSession,
    credential_configuration_id: String,
    proofs: Option<Proofs>,
    credential_response_encryption: Option<CredentialResponseEncryption>,
    dpop_proof_jwt: Option<String>,
    reallyme_zk_v1_issuance: Option<ReallyMeZkV1IssuanceRequest>,
) -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    let configuration = session
        .issuer_metadata
        .credential_configurations_supported
        .get(&credential_configuration_id)
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    if matches!(configuration.format, CredentialFormat::ReallyMeZkV1)
        != reallyme_zk_v1_issuance.is_some()
    {
        return Err(FlowError::new(FlowErrorReason::InvalidOpenId4VciState));
    }
    if session.issuer_metadata_profile != OpenId4VciIssuerMetadataProfile::OpenId4Vci {
        validate_etsi_credential_request_proofs(proofs.as_ref(), configuration.supports_proofs())
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    }
    let canonical_request = CredentialRequest {
        credential_configuration_id: Some(credential_configuration_id),
        credential_identifier: None,
        proofs,
        credential_response_encryption,
        reallyme_zk_v1_issuance,
    };
    let transport_request = WalletCredentialRequest::new_with_issuer_metadata(
        session.issuance.as_ref(),
        canonical_request.clone(),
        dpop_proof_jwt,
        session.issuer_metadata.as_ref(),
    )
    .map_err(|_| FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
    Ok(PreparedOpenId4VciCredentialRequest {
        issuer_nonce_binding: session.issuer_nonce_binding.clone(),
        canonical_request,
        transport_request,
        issuer_metadata: Arc::clone(&session.issuer_metadata),
    })
}

#[cfg(test)]
#[path = "prepare_credential_request_tests.rs"]
mod tests;
