// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Relying-party entitlement and consent capture.

mod apply_unregistered_attribute_policy;
mod bind_verified_request;
mod capture;
mod error;
mod evaluate;
mod plan_actions;
mod validate_actions;
mod validate_registration_certificate;
mod verify_registration_authorization;

pub use apply_unregistered_attribute_policy::UnregisteredAttributePolicy;
pub use capture::{
    capture_prepared_consent, prepare_consent_request, AuthorizedDisclosure, CapturedConsent,
    PreparedConsentRequest, TrustedConsentClock,
};
pub use error::{ConsentError, ConsentErrorReason, ConsentResult};
pub use evaluate::{
    evaluate_entitlement_at, unregistered_requested_attributes, MAX_CONSENT_SCOPE_ATTRIBUTES,
};
pub use plan_actions::consent_actions_for_satisfaction_plan;
pub use reallyme_wallet_storage::{
    ConsentCaptureStore, ConsentCaptureStoreError, ConsentCaptureStoreErrorReason, ConsentClaim,
};
pub use validate_registration_certificate::{
    evaluate_registered_entitlement_at, register_verifier_entitlement,
    validate_registration_certificate_path, validate_relying_party_registration_certificate,
    RegisteredVerifierEntitlement, RegistrationCertificatePathError,
    RegistrationCertificatePathValidator, ValidatedRegistrationCertificateChain,
};
pub use verify_registration_authorization::{
    register_verified_registration_authorization, RegistrationAuthorizationError,
    RegistrationAuthorizationFailureReason, RegistrationAuthorizationSource,
    RegistrationAuthorizationVerifier, VerifiedRegistrationAuthorization,
};

mod receipt;
pub use receipt::{
    bind_receipt_policy, capture_receipt_consent, consent_policy_digest,
    prepare_online_receipt_consent, prepare_reader_receipt_consent, AuthorizedReceiptDisclosure,
    CapturedReceiptConsent, ConsentPolicyVerifier, PolicyContextAuthorization,
    PreparedReceiptConsent, ReaderAuthorizationFacts, ReaderAuthorizationVerifier,
};

#[cfg(test)]
mod signed_request_tests;
