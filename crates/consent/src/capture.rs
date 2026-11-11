// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prepare and capture consent decisions after policy evaluation.

use reallyme_openid4vp_types::{ClientIdentifier, ClientIdentifierPrefix};
use reallyme_openid4vp_wallet::{VerifiedWalletRequest, WalletAuthorizationRequest};
use reallyme_wallet_storage::ConsentCaptureStore;
use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision,
    ConsentDerivationMode, ConsentRequest, ConsentScope, DisclosurePolicyDecision,
    NonEmptyIdentifier, RelyingPartyId, UnixTimestamp, VerifierEntitlement,
    CONSENT_REQUEST_DIGEST_BYTES,
};
use std::collections::BTreeSet;
use std::fmt;
use subtle::ConstantTimeEq;
use url::{Host, Url};
use zeroize::ZeroizeOnDrop;

#[path = "validate_capture.rs"]
mod validate_capture;
pub(crate) use validate_capture::validate_prepared_capture;

use crate::apply_unregistered_attribute_policy::apply_unregistered_attribute_policy;
use crate::bind_verified_request::{
    derive_consent_claim_scope, derive_verified_request_binding, VerifiedRequestBinding,
};
use crate::validate_actions::validate_actions;
use crate::{unregistered_requested_attributes, UnregisteredAttributePolicy};
use crate::{
    ConsentCaptureStoreErrorReason, ConsentClaim, ConsentError, ConsentErrorReason, ConsentResult,
    RegisteredVerifierEntitlement,
};

const MAX_CLIENT_IDENTIFIER_BYTES: usize = 512;

/// Consent request that has crossed the registration and entitlement boundary.
///
/// The inner DTO is deliberately not constructible by callers. Rendering code
/// may borrow it, while capture requires this proof-bearing wrapper.
#[derive(ZeroizeOnDrop)]
pub struct PreparedConsentRequest {
    request: ConsentRequest,
    entitlement_valid_until: UnixTimestamp,
    registration_freshness: Option<RegistrationFreshness>,
    bound_relying_party_id: Option<RelyingPartyId>,
    request_signer_sha256: Option<[u8; 32]>,
    request_expires_at: Option<UnixTimestamp>,
    unregistered_attributes: Vec<AttributeName>,
    /// Store key for the consent claim; derived from the verified client id
    /// when there is one, otherwise the relying-party identifier.
    claim_scope: Option<RelyingPartyId>,
}

/// Single-use authorization produced only after a durable nonce claim.
///
/// The record may be borrowed for evidence, but the authorization itself is
/// intentionally non-Clone and cannot be constructed from a serialized DTO.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct CapturedConsent {
    pub(crate) capture: ConsentCapture,
    valid_until: UnixTimestamp,
    request_signer_sha256: Option<[u8; 32]>,
}

/// Final response authorization after checking the actual disclosed scope.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct AuthorizedDisclosure {
    captured: CapturedConsent,
    disclosed_scope: ConsentScope,
}

impl AuthorizedDisclosure {
    /// Exclusive deadline after which the response must not be sent.
    ///
    /// The dispatcher enforces this at I/O time, as for receipt consent; the
    /// authorization itself cannot observe when the response leaves.
    #[must_use]
    pub const fn valid_until(&self) -> UnixTimestamp {
        self.captured.valid_until
    }

    /// Borrow the captured decision for transaction evidence.
    #[must_use]
    pub const fn record(&self) -> &ConsentCapture {
        self.captured.record()
    }

    /// Borrow the attributes authorized for the final response.
    #[must_use]
    pub const fn disclosed_scope(&self) -> &ConsentScope {
        &self.disclosed_scope
    }
}

impl fmt::Debug for AuthorizedDisclosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedDisclosure(<redacted>)")
    }
}

impl CapturedConsent {
    /// Borrow the consent evidence without copying its authorization token.
    #[must_use]
    pub const fn record(&self) -> &ConsentCapture {
        &self.capture
    }

    /// Consume the decision for this exact live request and disclosed scope.
    pub fn authorize_final_disclosure(
        self,
        request: &VerifiedWalletRequest,
        disclosed_scope: ConsentScope,
        clock: &dyn TrustedConsentClock,
    ) -> ConsentResult<AuthorizedDisclosure> {
        self.validate_live_request(request)?;
        let now = clock.now();
        if now < self.capture.captured_at || now >= self.valid_until {
            return Err(ConsentError::new(ConsentErrorReason::EntitlementExpired));
        }
        self.authorize_scope(disclosed_scope)
    }

    pub(crate) fn validate_live_request(
        &self,
        request: &VerifiedWalletRequest,
    ) -> ConsentResult<()> {
        let binding = derive_verified_request_binding(request.request())?;
        if binding.request_nonce != self.capture.request_nonce
            || !bool::from(binding.request_digest.ct_eq(&self.capture.request_digest))
            || request
                .x509_request_signer()
                .map(|signer| *signer.leaf_certificate_sha256())
                != self.request_signer_sha256
        {
            return Err(ConsentError::new(
                ConsentErrorReason::RequestBindingMismatch,
            ));
        }
        Ok(())
    }

    pub(crate) fn authorize_scope(
        self,
        disclosed_scope: ConsentScope,
    ) -> ConsentResult<AuthorizedDisclosure> {
        if disclosed_scope.attributes.len() > crate::MAX_CONSENT_SCOPE_ATTRIBUTES {
            return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
        }
        let mut seen = BTreeSet::new();
        for attribute in &disclosed_scope.attributes {
            if !seen.insert(attribute)
                || !self
                    .capture
                    .selected_action
                    .scope
                    .attributes
                    .contains(attribute)
                || (self.capture.selected_action.kind == ConsentActionKind::Derive
                    && !self
                        .capture
                        .selected_action
                        .derivation_inputs
                        .iter()
                        .any(|input| {
                            input.attribute == *attribute
                                && input.mode == ConsentDerivationMode::Reveal
                        }))
            {
                return Err(ConsentError::new(
                    ConsentErrorReason::FinalDisclosureOutOfScope,
                ));
            }
        }
        Ok(AuthorizedDisclosure {
            captured: self,
            disclosed_scope,
        })
    }
}

impl fmt::Debug for CapturedConsent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapturedConsent(<redacted>)")
    }
}

#[derive(ZeroizeOnDrop)]
struct RegistrationFreshness {
    validated_at: UnixTimestamp,
    fresh_until: UnixTimestamp,
}

/// Trusted time source supplied by the host at the user decision boundary.
pub trait TrustedConsentClock {
    /// Return the current time from the host's trusted clock.
    fn now(&self) -> UnixTimestamp;
}

impl PreparedConsentRequest {
    pub(crate) fn authorization_valid_until(&self) -> UnixTimestamp {
        let registration_deadline = self
            .registration_freshness
            .as_ref()
            .map_or(self.entitlement_valid_until, |freshness| {
                self.entitlement_valid_until.min(freshness.fresh_until)
            });
        self.request_expires_at
            .map_or(registration_deadline, |deadline| {
                registration_deadline.min(deadline)
            })
    }

    /// The store claim for this request, shared by plain and receipt capture.
    pub(crate) fn consent_claim(&self) -> ConsentClaim<'_> {
        ConsentClaim {
            namespace: self
                .claim_scope
                .as_ref()
                .unwrap_or(&self.request.relying_party_id),
            relying_party_id: &self.request.relying_party_id,
            request_nonce: &self.request.request_nonce,
            retain_until: self.authorization_valid_until(),
        }
    }

    pub(crate) fn captured(&self, capture: ConsentCapture) -> CapturedConsent {
        CapturedConsent {
            capture,
            valid_until: self.authorization_valid_until(),
            request_signer_sha256: self.request_signer_sha256,
        }
    }

    /// Borrow the validated request for rendering or persistence.
    #[must_use]
    pub const fn request(&self) -> &ConsentRequest {
        &self.request
    }

    /// Requested attributes the relying party did not register.
    ///
    /// Per ARF EW-DM-44-027 (legacy RPRC_21) the host must warn the user about
    /// these when asking for approval, whichever `UnregisteredAttributePolicy`
    /// applies. An empty slice means every requested attribute is registered.
    #[must_use]
    pub fn unregistered_attributes(&self) -> &[AttributeName] {
        &self.unregistered_attributes
    }
}

/// Prepare a consent request for identity to render to the user.
///
/// The single-use nonce and the request digest are derived from the verified
/// request itself: the nonce is the verifier's `nonce`, and the digest covers
/// the canonical form of the complete verified Authorization Request Object.
/// Callers cannot substitute either value, so one verified request yields at
/// most one consent claim per verifier `client_id`. Claims for an
/// `x509_san_dns` client compare the DNS name without case.
///
/// `unregistered_policy` is the Wallet Provider's decision for requested
/// attributes outside the registration certificate.
pub fn prepare_consent_request(
    entitlement: &RegisteredVerifierEntitlement,
    verified_request: &VerifiedWalletRequest,
    requested_scope: ConsentScope,
    actions: Vec<ConsentAction>,
    unregistered_policy: UnregisteredAttributePolicy,
    now: UnixTimestamp,
) -> ConsentResult<PreparedConsentRequest> {
    let binding = derive_verified_request_binding(verified_request.request())?;
    let client_id = verified_request
        .request()
        .client_id
        .as_ref()
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
    if let Some(expected_signer) = entitlement.request_signer_sha256() {
        let actual_signer = verified_request
            .x509_request_signer()
            .ok_or_else(|| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
        if !bool::from(expected_signer.ct_eq(actual_signer.leaf_certificate_sha256())) {
            return Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch));
        }
    }
    let mut prepared = prepare_consent_request_for_client(
        entitlement,
        client_id,
        requested_scope,
        actions,
        binding,
        unregistered_policy,
        now,
    )?;
    prepared.claim_scope = Some(derive_consent_claim_scope(client_id)?);
    prepared.request_signer_sha256 = verified_request
        .x509_request_signer()
        .map(|signer| *signer.leaf_certificate_sha256());
    if let Some(expiry) = verified_request.request().exp {
        let expiry = i64::try_from(expiry)
            .ok()
            .and_then(|seconds| UnixTimestamp::from_seconds(seconds).ok())
            .ok_or_else(|| ConsentError::new(ConsentErrorReason::RequestBindingMismatch))?;
        if now >= expiry {
            return Err(ConsentError::new(ConsentErrorReason::RequestExpired));
        }
        prepared.request_expires_at = Some(expiry);
    }
    Ok(prepared)
}

pub(crate) fn prepare_consent_request_for_client(
    entitlement: &RegisteredVerifierEntitlement,
    client_id: &ClientIdentifier,
    requested_scope: ConsentScope,
    actions: Vec<ConsentAction>,
    binding: VerifiedRequestBinding,
    unregistered_policy: UnregisteredAttributePolicy,
    now: UnixTimestamp,
) -> ConsentResult<PreparedConsentRequest> {
    validate_client_binding(entitlement, client_id)?;
    if now < entitlement.validated_at() || now >= entitlement.fresh_until() {
        return Err(ConsentError::new(
            ConsentErrorReason::RegistrationCertificateStale,
        ));
    }
    let mut prepared = prepare_consent_request_from_entitlement(
        entitlement.entitlement(),
        requested_scope,
        actions,
        binding.request_nonce,
        binding.request_digest,
        unregistered_policy,
        now,
    )?;
    prepared.registration_freshness = Some(RegistrationFreshness {
        validated_at: entitlement.validated_at(),
        fresh_until: entitlement.fresh_until(),
    });
    prepared.bound_relying_party_id = Some(entitlement.entitlement().relying_party_id.clone());
    Ok(prepared)
}

fn validate_client_binding(
    entitlement: &RegisteredVerifierEntitlement,
    client_id: &ClientIdentifier,
) -> ConsentResult<()> {
    if let Some(authenticated_client_id) = entitlement.authenticated_client_id() {
        return if authenticated_client_id == client_id {
            Ok(())
        } else {
            Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch))
        };
    }
    if client_id.identifier().len() > MAX_CLIENT_IDENTIFIER_BYTES {
        return Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch));
    }
    let matching = match client_id.prefix() {
        ClientIdentifierPrefix::X509SanDns => {
            let rp = Url::parse(entitlement.entitlement().relying_party_id.as_str())
                .map_err(|_| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
            let client_host = Host::parse(client_id.identifier())
                .map_err(|_| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
            matches!(client_host, Host::Domain(domain)
                if rp.scheme() == "https"
                    && rp.host_str().is_some_and(|host| host.eq_ignore_ascii_case(&domain)))
        }
        ClientIdentifierPrefix::X509Hash => false,
        ClientIdentifierPrefix::None
        | ClientIdentifierPrefix::RedirectUri
        | ClientIdentifierPrefix::OpenIdFederation
        | ClientIdentifierPrefix::DecentralizedIdentifier
        | ClientIdentifierPrefix::VerifierAttestation
        | ClientIdentifierPrefix::Origin => false,
    };
    if matching {
        Ok(())
    } else {
        Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch))
    }
}

pub(crate) fn prepare_consent_request_from_entitlement(
    entitlement: &VerifierEntitlement,
    mut requested_scope: ConsentScope,
    mut actions: Vec<ConsentAction>,
    request_nonce: NonEmptyIdentifier,
    request_digest: [u8; CONSENT_REQUEST_DIGEST_BYTES],
    unregistered_policy: UnregisteredAttributePolicy,
    now: UnixTimestamp,
) -> ConsentResult<PreparedConsentRequest> {
    // ARF EW-DM-44-027 (legacy RPRC_21): the User is warned about attributes
    // the relying party did not register, and the Wallet Provider's policy
    // decides whether they stay in the request.
    let unregistered_attributes =
        unregistered_requested_attributes(entitlement, &requested_scope, now)?;
    apply_unregistered_attribute_policy(
        unregistered_policy,
        &unregistered_attributes,
        &mut requested_scope,
        &mut actions,
    )?;
    // Record the warning in the decision itself; the capture must echo it.
    let policy_decision = if unregistered_attributes.is_empty() {
        DisclosurePolicyDecision::Allowed
    } else {
        DisclosurePolicyDecision::AllowedWithUnregisteredRequest
    };
    validate_actions(&actions, &requested_scope)?;
    if request_digest.iter().all(|byte| *byte == 0) {
        return Err(ConsentError::new(
            ConsentErrorReason::RequestBindingMismatch,
        ));
    }

    requested_scope.attributes.sort();
    for action in &mut actions {
        action.scope.attributes.sort();
    }

    Ok(PreparedConsentRequest {
        request: ConsentRequest {
            relying_party_id: entitlement.relying_party_id.clone(),
            requested_scope,
            policy_decision,
            actions,
            request_nonce,
            request_digest,
            created_at: now,
        },
        entitlement_valid_until: entitlement.valid_until,
        registration_freshness: None,
        bound_relying_party_id: None,
        request_signer_sha256: None,
        request_expires_at: None,
        unregistered_attributes,
        claim_scope: None,
    })
}

/// Persistently capture a consent decision after policy evaluation.
fn capture_consent(capture: ConsentCapture) -> ConsentResult<ConsentCapture> {
    if capture.policy_decision == DisclosurePolicyDecision::Denied {
        return Err(ConsentError::new(ConsentErrorReason::PolicyDenied));
    }
    if capture.user_decision == ConsentDecision::Rejected {
        return Err(ConsentError::new(ConsentErrorReason::UserRejected));
    }

    Ok(capture)
}

/// Capture consent after checking it matches the prepared request.
pub fn capture_prepared_consent(
    prepared: PreparedConsentRequest,
    capture: ConsentCapture,
    clock: &dyn TrustedConsentClock,
    store: &mut dyn ConsentCaptureStore,
) -> ConsentResult<CapturedConsent> {
    let captured = validate_prepared_capture(&prepared, capture, clock)?;
    store
        .claim_capture(&prepared.consent_claim(), None)
        .map_err(|error| {
            ConsentError::new(match error.reason {
                ConsentCaptureStoreErrorReason::AlreadyClaimed => {
                    ConsentErrorReason::CaptureAlreadyUsed
                }
                ConsentCaptureStoreErrorReason::Unavailable
                | ConsentCaptureStoreErrorReason::ReceiptUnsupported => {
                    ConsentErrorReason::CaptureStoreUnavailable
                }
            })
        })?;
    Ok(prepared.captured(captured))
}

fn scopes_match(left: &ConsentScope, right: &ConsentScope) -> bool {
    left.attributes.len() == right.attributes.len()
        && left.attributes.iter().collect::<BTreeSet<_>>()
            == right.attributes.iter().collect::<BTreeSet<_>>()
}

fn actions_match(left: &ConsentAction, right: &ConsentAction) -> bool {
    left.kind == right.kind
        && left.derivation_id == right.derivation_id
        && left.derivation_inputs == right.derivation_inputs
        && scopes_match(&left.scope, &right.scope)
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
