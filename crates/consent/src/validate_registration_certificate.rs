// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate relying-party registration evidence before consent.

use reallyme_openid4vp_types::ClientIdentifier;
use reallyme_trust_x509::{
    screen_chain_policy_only_no_path_validation, X509Certificate, X509Chain, X509Policy,
};
use reallyme_wallet_types::{
    ConsentScope, DisclosurePolicyDecision, UnixTimestamp, VerifierEntitlement,
};
use time::OffsetDateTime;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{evaluate_entitlement_at, ConsentError, ConsentErrorReason, ConsentResult};

const MAX_REGISTRATION_VALIDATION_AGE_SECONDS: i64 = 60;

/// Typed failure returned by an injected RFC 5280/trust-list path validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCertificatePathError {
    /// The chain did not terminate at an authorized trust anchor.
    UntrustedPath,
    /// Certificate signatures or constraints were invalid.
    InvalidPath,
    /// Revocation or status evidence rejected the path.
    Revoked,
}

/// Cryptographic and trust-list path-validation boundary.
pub trait RegistrationCertificatePathValidator {
    /// Validate the complete path and return claims authenticated by the evidence.
    ///
    /// Implementations must derive the relying-party identifier, authorized
    /// scope, and expiry from the signed registration evidence. They must not
    /// copy entitlement claims supplied by an untrusted request.
    fn validate_registration_certificate_path(
        &self,
        chain: &X509Chain,
        now: OffsetDateTime,
    ) -> Result<VerifierEntitlement, RegistrationCertificatePathError>;
}

/// Chain and entitlement token constructible only after path validation succeeds.
pub struct ValidatedRegistrationCertificateChain<'a> {
    chain: &'a X509Chain,
    entitlement: VerifierEntitlement,
    validated_at: UnixTimestamp,
    fresh_until: UnixTimestamp,
}

// The entitlement wipes itself when dropped; only the timestamps remain.
impl Drop for ValidatedRegistrationCertificateChain<'_> {
    fn drop(&mut self) {
        self.validated_at.zeroize();
        self.fresh_until.zeroize();
    }
}

impl ZeroizeOnDrop for ValidatedRegistrationCertificateChain<'_> {}

/// Entitlement authenticated by an accepted relying-party registration chain.
#[derive(ZeroizeOnDrop)]
pub struct RegisteredVerifierEntitlement {
    entitlement: VerifierEntitlement,
    validated_at: UnixTimestamp,
    fresh_until: UnixTimestamp,
    authenticated_client_id: Option<ClientIdentifier>,
    request_signer_sha256: Option<[u8; 32]>,
}

impl RegisteredVerifierEntitlement {
    pub(crate) const fn entitlement(&self) -> &VerifierEntitlement {
        &self.entitlement
    }

    pub(crate) const fn fresh_until(&self) -> UnixTimestamp {
        self.fresh_until
    }

    pub(crate) const fn validated_at(&self) -> UnixTimestamp {
        self.validated_at
    }

    pub(crate) const fn authenticated_client_id(&self) -> Option<&ClientIdentifier> {
        self.authenticated_client_id.as_ref()
    }

    pub(crate) const fn request_signer_sha256(&self) -> Option<&[u8; 32]> {
        self.request_signer_sha256.as_ref()
    }

    pub(crate) fn from_verified_registration(
        entitlement: VerifierEntitlement,
        validated_at: UnixTimestamp,
        fresh_until: UnixTimestamp,
        authenticated_client_id: ClientIdentifier,
        request_signer_sha256: [u8; 32],
    ) -> Self {
        Self {
            entitlement,
            validated_at,
            fresh_until,
            authenticated_client_id: Some(authenticated_client_id),
            request_signer_sha256: Some(request_signer_sha256),
        }
    }
}

/// Perform cryptographic path validation and construct the validated token.
pub fn validate_registration_certificate_path<'a>(
    chain: &'a X509Chain,
    validator: &dyn RegistrationCertificatePathValidator,
    now: UnixTimestamp,
) -> ConsentResult<ValidatedRegistrationCertificateChain<'a>> {
    let validation_time = offset_datetime_from_unix(now)?;
    let entitlement = validator
        .validate_registration_certificate_path(chain, validation_time)
        .map_err(|_| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))?;
    let fresh_until_seconds = now
        .as_seconds()
        .checked_add(MAX_REGISTRATION_VALIDATION_AGE_SECONDS)
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))?;
    let fresh_until = UnixTimestamp::from_seconds(fresh_until_seconds)
        .map_err(|_| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))?;
    Ok(ValidatedRegistrationCertificateChain {
        chain,
        entitlement,
        validated_at: now,
        fresh_until,
    })
}

/// Screen already path-validated RP registration evidence and bind it to the entitlement.
///
/// This function deliberately performs only wallet-owned checks: deterministic
/// certificate policy screening through the identity trust crate and RP
/// identifier binding through the leaf DNS subjectAltName. Full trust-list,
/// path-building, revocation, and remote status validation are supplied by the
/// SDK or verifier service before this function is called.
pub fn validate_relying_party_registration_certificate(
    validated_chain: &ValidatedRegistrationCertificateChain<'_>,
    policy: &X509Policy,
    now: UnixTimestamp,
) -> ConsentResult<DisclosurePolicyDecision> {
    if now < validated_chain.validated_at || now >= validated_chain.fresh_until {
        return Err(ConsentError::new(
            ConsentErrorReason::RegistrationCertificateStale,
        ));
    }
    let now = offset_datetime_from_unix(now)?;
    let chain = validated_chain.chain;
    let entitlement = &validated_chain.entitlement;
    screen_chain_policy_only_no_path_validation(chain, now, policy)
        .map_err(|_| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))?;

    let leaf = chain.leaf().ok_or(ConsentError::new(
        ConsentErrorReason::RegistrationCertificateInvalid,
    ))?;
    if !leaf_dns_san_matches_relying_party(leaf, entitlement) {
        return Err(ConsentError::new(
            ConsentErrorReason::RegistrationCertificateRelyingPartyMismatch,
        ));
    }
    if entitlement.valid_until.as_seconds() > leaf.not_after.unix_timestamp() {
        return Err(ConsentError::new(
            ConsentErrorReason::RegistrationCertificateInvalid,
        ));
    }

    Ok(DisclosurePolicyDecision::Allowed)
}

/// Validate registration evidence and return an opaque entitlement token.
pub fn register_verifier_entitlement(
    validated_chain: &ValidatedRegistrationCertificateChain<'_>,
    policy: &X509Policy,
    now: UnixTimestamp,
) -> ConsentResult<RegisteredVerifierEntitlement> {
    validate_relying_party_registration_certificate(validated_chain, policy, now)?;
    evaluate_entitlement_at(
        &validated_chain.entitlement,
        &validated_chain.entitlement.authorized_scope,
        now,
    )?;
    Ok(RegisteredVerifierEntitlement {
        entitlement: validated_chain.entitlement.clone(),
        validated_at: validated_chain.validated_at,
        fresh_until: validated_chain.fresh_until,
        authenticated_client_id: None,
        request_signer_sha256: None,
    })
}

/// Validate registration evidence and then evaluate the requested attribute scope.
///
/// Like `evaluate_entitlement_at`, this refuses any unregistered attribute; it
/// does not apply the Wallet Provider's `UnregisteredAttributePolicy`.
pub fn evaluate_registered_entitlement_at(
    requested: &ConsentScope,
    validated_chain: &ValidatedRegistrationCertificateChain<'_>,
    policy: &X509Policy,
    now: UnixTimestamp,
) -> ConsentResult<DisclosurePolicyDecision> {
    validate_relying_party_registration_certificate(validated_chain, policy, now)?;
    evaluate_entitlement_at(&validated_chain.entitlement, requested, now)
}

fn offset_datetime_from_unix(timestamp: UnixTimestamp) -> ConsentResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(timestamp.as_seconds())
        .map_err(|_| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))
}

fn leaf_dns_san_matches_relying_party(
    leaf: &X509Certificate,
    entitlement: &VerifierEntitlement,
) -> bool {
    let relying_party_id = entitlement.relying_party_id.as_str();
    leaf.san_dns
        .iter()
        .any(|dns_name| dns_name_matches_relying_party_id(dns_name, relying_party_id))
}

fn dns_name_matches_relying_party_id(dns_name: &str, relying_party_id: &str) -> bool {
    if dns_name.eq_ignore_ascii_case(relying_party_id) {
        return true;
    }

    let Ok(url) = Url::parse(relying_party_id) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }

    url.host_str()
        .is_some_and(|host| dns_name.eq_ignore_ascii_case(host))
}

#[cfg(test)]
#[path = "validate_registration_certificate_tests.rs"]
mod tests;
