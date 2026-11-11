// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated state retained across one OpenID4VCI issuance interaction.

use openid4vci_types::{CredentialRequest, CredentialResponse, IssuerMetadata};
use reallyme_openid4vci_wallet::{CredentialOfferGrantType, ValidatedIssuance};
use reallyme_wallet_attestation::WalletUnitAttestation;
use reallyme_wallet_types::{
    CredentialReusePolicySelection, KeyHandleId, NonEmptyIdentifier,
    OpenId4VciIssuerMetadataProfile,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{FlowResult, IssuanceState};

/// The user's decision for one validated issuance interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceConsentDecision {
    /// The user approved the displayed issuer and credential configurations.
    Approved,
    /// The user declined this issuance interaction.
    Rejected,
}

/// Display data the host must present before obtaining issuance consent.
pub struct IssuanceConsentRequest<'a> {
    pub(super) credential_issuer: &'a str,
    pub(super) credential_configuration_ids: &'a [String],
    pub(super) grant_type: CredentialOfferGrantType,
}

impl<'a> IssuanceConsentRequest<'a> {
    /// The issuer authenticated by the validated credential offer.
    #[must_use]
    pub const fn credential_issuer(&self) -> &'a str {
        self.credential_issuer
    }

    /// The exact configurations selected from the validated offer.
    #[must_use]
    pub const fn credential_configuration_ids(&self) -> &'a [String] {
        self.credential_configuration_ids
    }

    /// The validated grant selected for this interaction.
    #[must_use]
    pub const fn grant_type(&self) -> CredentialOfferGrantType {
        self.grant_type
    }
}

/// Host-owned user interaction for one issuance consent decision.
pub trait IssuanceConsentProvider {
    /// Obtain the user's decision for the validated offer shown by the host.
    fn capture_issuance_consent(
        &mut self,
        request: IssuanceConsentRequest<'_>,
    ) -> FlowResult<IssuanceConsentDecision>;
}

/// Deferred issuance metadata needed to resume polling.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct DeferredIssuanceStatus {
    /// Issuer-provided deferred credential transaction id.
    pub transaction_id: NonEmptyIdentifier,
    /// Positive polling interval in seconds.
    pub interval_seconds: u64,
}

/// Pure OpenID4VCI issuance session state owned by wallet-core.
///
/// `Clone` supports transactional injected transports: failed provider calls
/// leave the caller's borrowed state unchanged.
#[derive(Clone)]
pub struct OpenId4VciIssuanceSession {
    pub(crate) offer_digest: Zeroizing<[u8; 32]>,
    pub(crate) credential_submission_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) state: IssuanceState,
    pub(crate) issuer_nonce_binding: Option<reallyme_wallet_types::IssuerNonceBinding>,
    pub(crate) issuance: std::sync::Arc<ValidatedIssuance>,
    pub(crate) issuer_metadata: std::sync::Arc<IssuerMetadata>,
    pub(crate) grant_type: CredentialOfferGrantType,
    pub(crate) credential_issuer: String,
    pub(crate) credential_configuration_ids: Vec<String>,
    pub(crate) credential_reuse_policies: Vec<CredentialReusePolicySelection>,
    pub(crate) issuer_metadata_profile: OpenId4VciIssuerMetadataProfile,
    pub(crate) transaction_code: Option<openid4vci_types::TxCode>,
    pub(crate) authorization_code_issuer_state: Option<String>,
    pub(crate) credential_request: Option<CredentialRequest>,
    pub(crate) credential_binding_key_handle_ids: Vec<KeyHandleId>,
    pub(crate) wallet_unit_attestation: Option<WalletUnitAttestation>,
    pub(crate) credential_response: Option<CredentialResponse>,
    pub(crate) deferred_issuance: Option<DeferredIssuanceStatus>,
    pub(crate) access_token_binding_handle: Option<NonEmptyIdentifier>,
}

impl OpenId4VciIssuanceSession {
    /// Borrow the immutable authenticated nonce binding retained in snapshots.
    pub const fn issuer_nonce_binding(&self) -> Option<&reallyme_wallet_types::IssuerNonceBinding> {
        self.issuer_nonce_binding.as_ref()
    }

    /// Exact Nonce Endpoint authenticated with the bound issuer metadata.
    pub fn credential_nonce_endpoint(&self) -> Option<&str> {
        self.issuer_metadata.nonce_endpoint.as_deref()
    }

    /// Return the current issuance state.
    #[must_use]
    pub const fn state(&self) -> &IssuanceState {
        &self.state
    }

    /// Return the metadata-bound Credential Issuer identifier.
    #[must_use]
    pub fn credential_issuer(&self) -> &str {
        &self.credential_issuer
    }

    /// Return the configuration identifiers authorized for this interaction.
    #[must_use]
    pub fn credential_configuration_ids(&self) -> &[String] {
        self.credential_configuration_ids.as_slice()
    }

    /// Return immutable reuse-policy selections for offered configurations.
    #[must_use]
    pub fn credential_reuse_policies(&self) -> &[CredentialReusePolicySelection] {
        self.credential_reuse_policies.as_slice()
    }

    /// Return the issuer-metadata profile enforced for this session.
    #[must_use]
    pub const fn issuer_metadata_profile(&self) -> OpenId4VciIssuerMetadataProfile {
        self.issuer_metadata_profile
    }

    /// Return the grant selected and validated for this issuance.
    #[must_use]
    pub const fn grant_type(&self) -> CredentialOfferGrantType {
        self.grant_type
    }

    /// Borrow the metadata-bound issuance required by protocol builders.
    #[must_use]
    pub fn validated_issuance(&self) -> &ValidatedIssuance {
        self.issuance.as_ref()
    }

    /// Borrow issuer state authenticated by the resolved Credential Offer.
    #[must_use]
    pub fn authorization_code_issuer_state(&self) -> Option<&str> {
        self.authorization_code_issuer_state.as_deref()
    }

    /// Return the RFC 8707 resource when metadata names authorization servers.
    #[must_use]
    pub fn authorization_request_resource(&self) -> Option<&str> {
        self.issuer_metadata
            .authorization_servers
            .as_ref()
            .map(|_| self.credential_issuer.as_str())
    }

    /// Borrow the bound credential request when one has been submitted.
    #[must_use]
    pub const fn credential_request(&self) -> Option<&CredentialRequest> {
        self.credential_request.as_ref()
    }

    /// Borrow ordered credential-binding keys authenticated from proofs.
    #[must_use]
    pub fn credential_binding_key_handle_ids(&self) -> &[KeyHandleId] {
        self.credential_binding_key_handle_ids.as_slice()
    }

    /// Borrow the verified wallet unit attestation bound to this flow.
    #[must_use]
    pub const fn wallet_unit_attestation(&self) -> Option<&WalletUnitAttestation> {
        self.wallet_unit_attestation.as_ref()
    }

    /// Borrow the issuer response recorded for this flow.
    #[must_use]
    pub const fn credential_response(&self) -> Option<&CredentialResponse> {
        self.credential_response.as_ref()
    }

    /// Borrow deferred polling coordinates when issuance is incomplete.
    #[must_use]
    pub const fn deferred_issuance(&self) -> Option<&DeferredIssuanceStatus> {
        self.deferred_issuance.as_ref()
    }

    /// Borrow the exact transport-owned token handle bound to this flow.
    #[must_use]
    pub const fn access_token_binding_handle(&self) -> Option<&NonEmptyIdentifier> {
        self.access_token_binding_handle.as_ref()
    }
}
