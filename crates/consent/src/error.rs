// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet consent operations.

use thiserror::Error;

/// Result type for consent operations.
pub type ConsentResult<T> = Result<T, ConsentError>;

/// Typed consent error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet consent operation failed: {reason}")]
pub struct ConsentError {
    /// Stable reason code.
    pub reason: ConsentErrorReason,
}

impl ConsentError {
    /// Construct a consent error from a stable reason.
    #[must_use]
    pub const fn new(reason: ConsentErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable consent failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConsentErrorReason {
    /// Authenticated reader/session facts were inconsistent or stale.
    #[error("reader_authentication_rejected")]
    ReaderAuthenticationRejected,
    /// A mandatory policy cannot be interpreted or satisfied by the provider.
    #[error("policy_unsupported")]
    PolicyUnsupported,
    /// Approved terms differ from the prepared authenticated context.
    #[error("policy_context_mismatch")]
    PolicyContextMismatch,
    /// Atomic receipt persistence failed; no authorization escaped.
    #[error("receipt_store_unavailable")]
    ReceiptStoreUnavailable,

    /// Relying-party entitlement has expired.
    #[error("entitlement_expired")]
    EntitlementExpired,
    /// Requested scope was empty.
    #[error("empty_requested_scope")]
    EmptyRequestedScope,
    /// Attribute lists exceed the deterministic evaluation bound.
    #[error("scope_too_large")]
    ScopeTooLarge,
    /// Relying party is not entitled to request at least one attribute.
    #[error("attribute_not_authorized")]
    AttributeNotAuthorized,
    /// Relying-party registration certificate failed trust policy screening.
    #[error("registration_certificate_invalid")]
    RegistrationCertificateInvalid,
    /// The path and revocation decision is too old for this consent.
    #[error("registration_certificate_stale")]
    RegistrationCertificateStale,
    /// Registration certificate does not bind the evaluated relying-party id.
    #[error("registration_certificate_relying_party_mismatch")]
    RegistrationCertificateRelyingPartyMismatch,
    /// Disclosure policy denied the request.
    #[error("policy_denied")]
    PolicyDenied,
    /// User rejected the disclosure or derivation.
    #[error("user_rejected")]
    UserRejected,
    /// Captured relying party did not match the evaluated entitlement.
    #[error("relying_party_mismatch")]
    RelyingPartyMismatch,
    /// Consent action list was empty.
    #[error("missing_consent_action")]
    MissingConsentAction,
    /// Captured consent does not match the prepared request transcript.
    #[error("request_binding_mismatch")]
    RequestBindingMismatch,
    /// The verified request's own expiry (`exp`) has passed.
    #[error("request_expired")]
    RequestExpired,
    /// Derivation actions must carry a stable derivation identifier.
    #[error("derivation_identifier_missing")]
    DerivationIdentifierMissing,
    /// Direct disclosure actions must not carry derivation identifiers.
    #[error("disclosure_derivation_identifier_present")]
    DisclosureDerivationIdentifierPresent,
    /// Identity policy produced a satisfaction plan wallet-core cannot render safely.
    #[error("invalid_satisfaction_plan")]
    InvalidSatisfactionPlan,
    /// This request was already captured and cannot authorize another disclosure.
    #[error("capture_already_used")]
    CaptureAlreadyUsed,
    /// Durable single-use claim could not be committed.
    #[error("capture_store_unavailable")]
    CaptureStoreUnavailable,
    /// Final presentation output reveals an attribute outside the selected action.
    #[error("final_disclosure_out_of_scope")]
    FinalDisclosureOutOfScope,
    /// Verified presentation client does not match registration evidence.
    #[error("client_binding_mismatch")]
    ClientBindingMismatch,
}
