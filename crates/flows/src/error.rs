// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet flow transitions.

use thiserror::Error;

/// Result type for wallet flow transitions.
pub type FlowResult<T> = Result<T, FlowError>;

/// Typed flow error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet flow transition failed: {reason}")]
pub struct FlowError {
    /// Stable reason code.
    pub reason: FlowErrorReason,
}

impl FlowError {
    /// Construct a flow error from a stable reason.
    #[must_use]
    pub const fn new(reason: FlowErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable flow failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FlowErrorReason {
    /// Transition is invalid for the current state.
    #[error("invalid_transition")]
    InvalidTransition,
    /// OpenID4VCI data failed validation in its owning protocol crate.
    #[error("invalid_openid4vci_state")]
    InvalidOpenId4VciState,
    /// Credential reuse metadata is malformed for the selected EUDI profile.
    #[error("invalid_credential_reuse_policy")]
    InvalidCredentialReusePolicy,
    /// No wallet-supported method satisfies the issuer's credential reuse policy.
    #[error("unsupported_credential_reuse_policy")]
    UnsupportedCredentialReusePolicy,
    /// Authenticated issuer metadata does not satisfy the selected profile.
    #[error("invalid_issuer_metadata_profile")]
    InvalidIssuerMetadataProfile,
    /// A referenced OpenID4VCI credential offer needs an injected resolver.
    #[error("credential_offer_resolution_required")]
    CredentialOfferResolutionRequired,
    /// A pre-authorized token request was requested for an offer without that grant.
    #[error("pre_authorized_code_grant_required")]
    PreAuthorizedCodeGrantRequired,
    /// The issuer declared a transaction-code requirement and no code was supplied.
    #[error("transaction_code_required")]
    TransactionCodeRequired,
    /// A transaction code was supplied even though the offer did not declare one.
    #[error("transaction_code_unexpected")]
    TransactionCodeUnexpected,
    /// The supplied transaction code does not match the offer metadata.
    #[error("transaction_code_invalid_for_offer")]
    TransactionCodeInvalidForOffer,
    /// Injected OpenID4VCI issuer transport rejected the operation.
    #[error("openid4vci_issuer_transport_rejected")]
    OpenId4VciIssuerTransportRejected,
    /// A credential dispatch may have reached the issuer and needs reconciliation.
    #[error("credential_submission_uncertain")]
    CredentialSubmissionUncertain,
    /// A deferred poll was attempted before the issuer's polling interval elapsed.
    #[error("deferred_poll_too_early")]
    DeferredPollTooEarly,
    /// Deferred issuance exceeded its attempt or waiting bound.
    #[error("deferred_issuance_expired")]
    DeferredIssuanceExpired,
    /// An opaque bearer-token handle belongs to a different issuance session.
    #[error("access_token_session_mismatch")]
    AccessTokenSessionMismatch,
    /// A nonce-enabled issuer cannot be used until a trusted nonce is bound to the proof.
    #[error("credential_proof_nonce_binding_unavailable")]
    CredentialProofNonceBindingUnavailable,
    /// Issuance needs a wallet unit attestation before credential request construction.
    #[error("wallet_unit_attestation_required")]
    WalletUnitAttestationRequired,
    /// Wallet unit attestation failed lifecycle validation.
    #[error("invalid_wallet_unit_attestation")]
    InvalidWalletUnitAttestation,
    /// Issued credential receipt or inventory import failed validation.
    #[error("invalid_credential_receipt")]
    InvalidCredentialReceipt,
    /// Identity satisfaction plan could not become an authorized presentation consent request.
    #[error("invalid_presentation_satisfaction")]
    InvalidPresentationSatisfaction,
    /// The captured consent expired before the response was authorized.
    #[error("presentation_consent_expired")]
    PresentationConsentExpired,
    /// The live request is not the request the user consented to.
    #[error("presentation_request_mismatch")]
    PresentationRequestMismatch,
    /// Contact delivery limits are internally inconsistent.
    #[error("invalid_contact_limits")]
    InvalidContactLimits,
    /// Contact delivery input failed deterministic validation.
    #[error("invalid_contact_input")]
    InvalidContactInput,
    /// Contact delivery message exceeded configured size limits.
    #[error("contact_message_too_large")]
    ContactMessageTooLarge,
    /// Contact delivery could not reserve its bounded payload buffer.
    #[error("contact_allocation_failed")]
    ContactAllocationFailed,
    /// Contact delivery frame exceeded configured size limits.
    #[error("contact_frame_too_large")]
    ContactFrameTooLarge,
    /// Contact delivery would require too many frames.
    #[error("contact_too_many_frames")]
    ContactTooManyFrames,
    /// Contact delivery session transcript binding did not match.
    #[error("contact_session_transcript_mismatch")]
    ContactSessionTranscriptMismatch,
    /// Contact delivery message has expired.
    #[error("contact_message_expired")]
    ContactMessageExpired,
}
