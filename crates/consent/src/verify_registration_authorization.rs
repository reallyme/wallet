// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bind host-authenticated registration scope to the exact signed VP client.

use reallyme_openid4vp_types::{ClientIdentifier, ClientIdentifierPrefix};
use reallyme_openid4vp_wallet::{VerifiedWalletRequest, WalletAuthorizationRequest};
use reallyme_wallet_types::{UnixTimestamp, VerifierEntitlement};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    evaluate_entitlement_at, ConsentError, ConsentErrorReason, ConsentResult,
    RegisteredVerifierEntitlement,
};

const MAX_REGISTRATION_DECISION_AGE_SECONDS: i64 = 60;

/// The authenticated source of a relying party's registered attribute scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum RegistrationAuthorizationSource {
    /// A signed and current wallet relying party registration credential.
    Wrprc,
    /// A signed, current response from the authoritative RP registrar.
    RegistrarRecord,
}

/// Stable failures from a host-owned registration authentication provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationAuthorizationFailureReason {
    /// Signed registration representation or registrar response was invalid.
    InvalidProof,
    /// Certification path or registrar authority was rejected.
    UntrustedAuthority,
    /// Current registration or credential status was invalid.
    InvalidStatus,
    /// Trust, registrar, or status service could not provide a current answer.
    EvidenceUnavailable,
    /// The registration does not identify the authenticated request signer.
    RequesterMismatch,
}

/// No untrusted input or backend text crosses the registration error boundary.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("registration authorization verification failed")]
pub struct RegistrationAuthorizationError {
    reason: RegistrationAuthorizationFailureReason,
}

impl RegistrationAuthorizationError {
    /// Construct a stable failure without retaining external evidence.
    pub const fn new(reason: RegistrationAuthorizationFailureReason) -> Self {
        Self { reason }
    }

    /// Return the fixed failure reason.
    pub const fn reason(self) -> RegistrationAuthorizationFailureReason {
        self.reason
    }
}

/// Host-authenticated authorization facts for one exact signed VP request.
///
/// Constructing this value is part of the trusted provider contract. The
/// provider must verify the WRPRC or registrar record, signer trust, current
/// status, and association to the WRPAC holder before returning it. Wallet
/// independently checks the exact request client and signing leaf binding.
#[derive(ZeroizeOnDrop)]
pub struct VerifiedRegistrationAuthorization {
    entitlement: VerifierEntitlement,
    authenticated_client_id: ClientIdentifier,
    request_signer_sha256: [u8; 32],
    validated_at: UnixTimestamp,
    fresh_until: UnixTimestamp,
    source: RegistrationAuthorizationSource,
}

impl VerifiedRegistrationAuthorization {
    /// Capture the provider's authenticated authorization decision.
    pub fn new(
        entitlement: VerifierEntitlement,
        authenticated_client_id: ClientIdentifier,
        request_signer_sha256: [u8; 32],
        validated_at: UnixTimestamp,
        fresh_until: UnixTimestamp,
        source: RegistrationAuthorizationSource,
    ) -> ConsentResult<Self> {
        if authenticated_client_id.prefix() != ClientIdentifierPrefix::X509Hash
            || request_signer_sha256.iter().all(|byte| *byte == 0)
            || validated_at > fresh_until
            || fresh_until > entitlement.valid_until
        {
            return Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch));
        }
        let max_fresh_until = validated_at
            .as_seconds()
            .checked_add(MAX_REGISTRATION_DECISION_AGE_SECONDS)
            .ok_or_else(|| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))?;
        if fresh_until.as_seconds() > max_fresh_until {
            return Err(ConsentError::new(
                ConsentErrorReason::RegistrationCertificateStale,
            ));
        }
        Ok(Self {
            entitlement,
            authenticated_client_id,
            request_signer_sha256,
            validated_at,
            fresh_until,
            source,
        })
    }

    /// Identify which authenticated source supplied the registration scope.
    pub const fn source(&self) -> RegistrationAuthorizationSource {
        self.source
    }
}

/// Identity-host boundary for EUDI registration and trust-service composition.
pub trait RegistrationAuthorizationVerifier {
    /// Authenticate the registration applicable to this exact verified request.
    ///
    /// This method must fail closed when the registrar, WRPRC signer, current
    /// status, or WRPAC association cannot be established. Network and trust
    /// service configuration belong in the host, not Wallet core.
    fn verify_registration_authorization(
        &self,
        request: &VerifiedWalletRequest,
        now: UnixTimestamp,
    ) -> Result<VerifiedRegistrationAuthorization, RegistrationAuthorizationError>;
}

/// Create a Wallet entitlement after checking host evidence against the signer.
pub fn register_verified_registration_authorization(
    verifier: &dyn RegistrationAuthorizationVerifier,
    request: &VerifiedWalletRequest,
    now: UnixTimestamp,
) -> ConsentResult<RegisteredVerifierEntitlement> {
    let client_id = request
        .request()
        .client_id
        .as_ref()
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
    let signer = request
        .x509_request_signer()
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
    let verified = verifier
        .verify_registration_authorization(request, now)
        .map_err(|_| ConsentError::new(ConsentErrorReason::RegistrationCertificateInvalid))?;
    if client_id != &verified.authenticated_client_id
        || !bool::from(
            signer
                .leaf_certificate_sha256()
                .ct_eq(&verified.request_signer_sha256),
        )
    {
        return Err(ConsentError::new(ConsentErrorReason::ClientBindingMismatch));
    }
    if now < verified.validated_at || now >= verified.fresh_until {
        return Err(ConsentError::new(
            ConsentErrorReason::RegistrationCertificateStale,
        ));
    }
    evaluate_entitlement_at(
        &verified.entitlement,
        &verified.entitlement.authorized_scope,
        now,
    )?;
    Ok(RegisteredVerifierEntitlement::from_verified_registration(
        verified.entitlement.clone(),
        verified.validated_at,
        verified.fresh_until,
        verified.authenticated_client_id.clone(),
        verified.request_signer_sha256,
    ))
}

#[cfg(test)]
#[path = "verify_registration_authorization_tests.rs"]
mod tests;
