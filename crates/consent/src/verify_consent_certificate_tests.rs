// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolve signer authority through SSI's real path builder and signature checks.

use reallyme_openid4vp_wallet::{
    BoundedX509CertificateChain, JoseRequestObjectVerification,
    JoseRequestObjectVerificationResolver, TrustedX509RequestObjectSigner, WalletError,
    WalletErrorReason, X509RequestObjectTrustDecision, X509TrustDecisionContext,
};
use reallyme_trust_core::{
    evaluate_trust_decision, SignatureVerifier, SignatureVerifyError, TrustConfig, TrustOutcome,
};
use reallyme_trust_x509::{
    certificate_subject_public_key_info, parse_cert_der, parse_cert_pem, PureRustSignatureVerifier,
    SubjectPublicKeyAlgorithm, TrustAnchorRequirement, X509Chain, X509Policy,
};
use time::OffsetDateTime;

use super::certificates::ROOT_PEM;

struct CertificateSignatures;
impl SignatureVerifier for CertificateSignatures {
    fn verify_chain(
        &self,
        chain: &X509Chain,
        _: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        // SSI's policy stage checks trusted time. Its portable backend checks
        // every certificate signature and supported path constraint here.
        PureRustSignatureVerifier::new()
            .verify_chain(chain)
            .map_err(|_| SignatureVerifyError::InvalidSignature)
    }
}

pub(super) struct Resolver {
    root_pem: &'static [u8],
}
impl Resolver {
    pub(super) const fn trusted() -> Self {
        Self { root_pem: ROOT_PEM }
    }

    pub(super) const fn with_root(root_pem: &'static [u8]) -> Self {
        Self { root_pem }
    }
}

impl JoseRequestObjectVerificationResolver for Resolver {
    fn resolve_request_object_verification(
        &self,
        _: &str,
        _: Option<&reallyme_openid4vp_types::ClientIdentifier>,
        chain: Option<&BoundedX509CertificateChain>,
        now_unix: u64,
    ) -> Result<JoseRequestObjectVerification, WalletError> {
        let chain = chain
            .ok_or_else(|| WalletError::new(WalletErrorReason::MissingX509CertificateChain))?;
        let malformed = || WalletError::new(WalletErrorReason::MalformedX509CertificateChain);
        let rejected = || WalletError::new(WalletErrorReason::X509CertificatePathRejected);
        let root = parse_cert_pem(self.root_pem).map_err(|_| malformed())?;
        let presented = chain
            .certificates_der()
            .map(|der| parse_cert_der(der).map_err(|_| malformed()))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = presented.first().ok_or_else(malformed)?;
        let subject = certificate_subject_public_key_info(&leaf.der).map_err(|_| malformed())?;
        if subject.algorithm != SubjectPublicKeyAlgorithm::P256 {
            return Err(WalletError::new(
                WalletErrorReason::UnsupportedX509CertificateAlgorithm,
            ));
        }
        let leaf_dns_sans = leaf.san_dns.clone();
        let valid_until = u64::try_from(leaf.not_after.unix_timestamp()).map_err(|_| rejected())?;
        let now = i64::try_from(now_unix)
            .ok()
            .and_then(|now| OffsetDateTime::from_unix_timestamp(now).ok())
            .ok_or_else(rejected)?;
        let decision = evaluate_trust_decision(
            &presented,
            &TrustConfig {
                trust_roots: vec![root.clone()],
                now,
                policy: X509Policy {
                    require_leaf_digital_signature: true,
                    require_leaf_not_self_issued: true,
                    minimum_ec_bits: Some(256),
                    trust_anchor_requirement: TrustAnchorRequirement::Rfc5280Ca,
                    ..X509Policy::default()
                },
                link_policy: Default::default(),
                evaluation: Default::default(),
                direct_trust: vec![],
            },
            &CertificateSignatures,
            None,
        )
        .map_err(|_| rejected())?;
        if decision.outcome() != TrustOutcome::Trusted {
            return Err(rejected());
        }
        let jwk = reallyme_crypto::jwk::Jwk::Ec(
            reallyme_crypto::jwk::p256_public_key_to_jwk(
                &subject.public_key,
                reallyme_crypto::jwk::JwkOptions {
                    alg: true,
                    use_sig: true,
                    use_enc: false,
                    kid: Some("test-key".into()),
                },
            )
            .map_err(|_| malformed())?,
        );
        let public = jwk.public_key_bytes().map_err(|_| malformed())?;
        // A trust receipt exists only after SSI has selected an authenticated
        // path to this configured root. Its identifiers bind actual root bytes.
        let context = X509TrustDecisionContext::new(
            1,
            *crypto_sha2_256::digest(self.root_pem).as_bytes(),
            *crypto_sha2_256::digest(&root.der).as_bytes(),
            now_unix,
            valid_until,
        )?;
        let signer = TrustedX509RequestObjectSigner::new(
            chain.clone(),
            public.clone(),
            leaf_dns_sans,
            context,
        )?;
        Ok(JoseRequestObjectVerification::new(jwk, public)
            .with_x509_trust_decision(X509RequestObjectTrustDecision::Trusted(signer)))
    }
}
