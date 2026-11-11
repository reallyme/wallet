// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::ClientIdentifier;
use reallyme_trust_x509::{
    BasicConstraints, CertificatePolicyId, ExtendedKeyUsagePurpose, KeyUsage, PublicKeyProfile,
    QcStatementId, QcStatements, QcType, X509Certificate, X509Chain, X509Policy,
    OID_EKU_SERVER_AUTH, OID_ETSI_QCS_QC_COMPLIANCE, OID_ETSI_QCS_QC_TYPE, OID_ETSI_QCT_WEB,
    OID_QEVCP_W,
};
use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision, ConsentScope,
    DisclosurePolicyDecision, NonEmptyIdentifier, UnixTimestamp, VerifierEntitlement,
    WalletTypesError,
};
use time::{Duration, OffsetDateTime};
use zeroize::ZeroizeOnDrop;

use super::{
    evaluate_registered_entitlement_at, register_verifier_entitlement,
    validate_registration_certificate_path, validate_relying_party_registration_certificate,
    RegistrationCertificatePathError, RegistrationCertificatePathValidator,
};
use crate::{
    capture_prepared_consent as capture_prepared_consent_with_store, CapturedConsent,
    ConsentCaptureStore, ConsentCaptureStoreError, ConsentCaptureStoreErrorReason,
    ConsentErrorReason, ConsentResult, PreparedConsentRequest, TrustedConsentClock,
};

fn prepare_consent_request(
    entitlement: &super::RegisteredVerifierEntitlement,
    requested_scope: ConsentScope,
    actions: Vec<ConsentAction>,
    request_nonce: NonEmptyIdentifier,
    request_digest: [u8; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
    now: UnixTimestamp,
) -> ConsentResult<PreparedConsentRequest> {
    let client_id = ClientIdentifier::parse("x509_san_dns:verifier.example")
        .map_err(|_| crate::ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
    crate::capture::prepare_consent_request_for_client(
        entitlement,
        &client_id,
        requested_scope,
        actions,
        crate::bind_verified_request::VerifiedRequestBinding {
            request_nonce,
            request_digest,
        },
        crate::UnregisteredAttributePolicy::WarnAndAllowAll,
        now,
    )
}

struct FixedClock(UnixTimestamp);

#[test]
fn registration_capabilities_wipe_owned_claims_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<super::ValidatedRegistrationCertificateChain<'_>>();
    assert_zeroize_on_drop::<super::RegisteredVerifierEntitlement>();
    assert_zeroize_on_drop::<crate::PreparedConsentRequest>();
    assert_zeroize_on_drop::<crate::CapturedConsent>();
    assert_zeroize_on_drop::<crate::AuthorizedDisclosure>();
}

impl TrustedConsentClock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        self.0
    }
}

struct AcceptCaptureStore;

impl ConsentCaptureStore for AcceptCaptureStore {
    fn claim_capture(
        &mut self,
        _claim: &crate::ConsentClaim<'_>,
        receipt: Option<&reallyme_wallet_types::ConsentReceipt>,
    ) -> Result<(), ConsentCaptureStoreError> {
        // This store keeps no receipts, so it must refuse one, not drop it.
        if receipt.is_some() {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::ReceiptUnsupported,
            ));
        }
        Ok(())
    }
}

fn capture_prepared_consent(
    prepared: PreparedConsentRequest,
    capture: ConsentCapture,
    clock: &dyn TrustedConsentClock,
) -> ConsentResult<CapturedConsent> {
    capture_prepared_consent_with_store(prepared, capture, clock, &mut AcceptCaptureStore)
}

struct AcceptPathValidator {
    entitlement: VerifierEntitlement,
}

impl RegistrationCertificatePathValidator for AcceptPathValidator {
    fn validate_registration_certificate_path(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<VerifierEntitlement, RegistrationCertificatePathError> {
        Ok(self.entitlement.clone())
    }
}

fn attr(value: &str) -> Result<AttributeName, WalletTypesError> {
    AttributeName::new(value.to_owned())
}

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(value: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(value)
}

fn entitlement(relying_party_id: &str) -> Result<VerifierEntitlement, WalletTypesError> {
    Ok(VerifierEntitlement {
        relying_party_id: id(relying_party_id)?,
        authorized_scope: ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        valid_until: timestamp(20)?,
    })
}

fn validator(relying_party_id: &str) -> Result<AcceptPathValidator, WalletTypesError> {
    Ok(AcceptPathValidator {
        entitlement: entitlement(relying_party_id)?,
    })
}

fn requested_scope(attribute: &str) -> Result<ConsentScope, WalletTypesError> {
    Ok(ConsentScope {
        attributes: vec![attr(attribute)?],
    })
}

fn policy() -> X509Policy {
    X509Policy {
        require_leaf_not_ca: true,
        require_intermediate_ca: true,
        required_leaf_eku_any_of: vec![ExtendedKeyUsagePurpose::ServerAuthentication],
        require_leaf_digital_signature: true,
        required_policy_any_of: vec![CertificatePolicyId::QevcpWeb],
        required_qc_statement_ids: vec![QcStatementId::Compliance, QcStatementId::Type],
        required_qc_type_any_of: vec![QcType::WebAuthentication],
        ..X509Policy::default()
    }
}

fn chain_for_dns(dns_name: &str) -> X509Chain {
    X509Chain {
        certs: vec![leaf_for_dns(dns_name), intermediate()],
    }
}

fn leaf_for_dns(dns_name: &str) -> X509Certificate {
    let mut profile = reallyme_trust_x509::CertificateProfile::default();
    profile.extended_key_usage = vec![ExtendedKeyUsagePurpose::ServerAuthentication];
    profile.certificate_policies = vec![CertificatePolicyId::QevcpWeb];
    profile.qc_statement_ids = vec![QcStatementId::Compliance, QcStatementId::Type];
    profile.qc_types = vec![QcType::WebAuthentication];
    profile.public_key = PublicKeyProfile::Ed25519;

    X509Certificate {
        der: Vec::new(),
        subject: "CN=verifier.example".to_owned(),
        issuer: "CN=issuer.example".to_owned(),
        subject_der: b"CN=verifier.example".to_vec(),
        issuer_der: b"CN=issuer.example".to_vec(),
        serial: vec![1],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + Duration::days(3650),
        spki_der: Vec::new(),
        signature_algorithm_oid: "1.2.840.10045.4.3.2".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            key_cert_sign: false,
            crl_sign: false,
            key_encipherment: false,
            key_agreement: false,
            content_commitment: false,
            data_encipherment: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: Some(vec![OID_EKU_SERVER_AUTH.to_owned()]),
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: vec![dns_name.to_owned()],
        san_ip: Vec::new(),
        certificate_policies: vec![OID_QEVCP_W.to_owned()],
        qc_statements: QcStatements {
            statement_ids: vec![
                OID_ETSI_QCS_QC_COMPLIANCE.to_owned(),
                OID_ETSI_QCS_QC_TYPE.to_owned(),
            ],
            qc_types: vec![OID_ETSI_QCT_WEB.to_owned()],
        },
        profile,
    }
}

fn intermediate() -> X509Certificate {
    X509Certificate {
        der: Vec::new(),
        subject: "CN=issuer.example".to_owned(),
        issuer: "CN=root.example".to_owned(),
        subject_der: b"CN=issuer.example".to_vec(),
        issuer_der: b"CN=root.example".to_vec(),
        serial: vec![2],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + Duration::days(3650),
        spki_der: Vec::new(),
        signature_algorithm_oid: "1.2.840.10045.4.3.2".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }),
        key_usage: Some(KeyUsage {
            digital_signature: false,
            key_cert_sign: true,
            crl_sign: true,
            key_encipherment: false,
            key_agreement: false,
            content_commitment: false,
            data_encipherment: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: QcStatements::default(),
        profile: reallyme_trust_x509::CertificateProfile::default(),
    }
}

#[test]
fn accepts_registration_certificate_for_relying_party_dns() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let path_validator = validator("https://verifier.example")?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;
    let decision =
        validate_relying_party_registration_certificate(&validated, &policy(), timestamp(10)?)?;

    assert_eq!(
        decision,
        reallyme_wallet_types::DisclosurePolicyDecision::Allowed
    );
    Ok(())
}

#[test]
fn evaluates_scope_after_registration_certificate_validation() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let path_validator = validator("https://verifier.example")?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;
    let decision = evaluate_registered_entitlement_at(
        &requested_scope("age_over_18")?,
        &validated,
        &policy(),
        timestamp(10)?,
    )?;

    assert_eq!(
        decision,
        reallyme_wallet_types::DisclosurePolicyDecision::Allowed
    );
    Ok(())
}

#[test]
fn rejects_registration_certificate_relying_party_mismatch() -> Result<(), TestError> {
    let chain = chain_for_dns("other.example");
    let path_validator = validator("https://verifier.example")?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;
    let result =
        validate_relying_party_registration_certificate(&validated, &policy(), timestamp(10)?);

    assert!(matches!(
        result,
        Err(error)
            if error.reason
                == ConsentErrorReason::RegistrationCertificateRelyingPartyMismatch
    ));
    Ok(())
}

#[test]
fn rejects_registration_certificate_policy_failure() -> Result<(), TestError> {
    let mut chain = chain_for_dns("verifier.example");
    if let Some(leaf) = chain.certs.first_mut() {
        // `profile` is the authoritative typed projection evaluated by
        // reallyme-trust-x509; keep the legacy lossless fields aligned for this
        // intentionally malformed fixture.
        leaf.profile.qc_types.clear();
        leaf.qc_statements.qc_types.clear();
    }

    let path_validator = validator("https://verifier.example")?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;

    let result =
        validate_relying_party_registration_certificate(&validated, &policy(), timestamp(10)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateInvalid
    ));
    Ok(())
}

#[test]
fn rejects_scope_after_valid_registration_if_attribute_is_unauthorized() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let path_validator = validator("https://verifier.example")?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;
    let result = evaluate_registered_entitlement_at(
        &requested_scope("family_name")?,
        &validated,
        &policy(),
        timestamp(10)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::AttributeNotAuthorized
    ));
    Ok(())
}

#[test]
fn registered_path_validation_expires_before_a_later_consent_request() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let mut path_validator = validator("https://verifier.example")?;
    path_validator.entitlement.valid_until = timestamp(200)?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;
    let registered = register_verifier_entitlement(&validated, &policy(), timestamp(10)?)?;
    let action = ConsentAction {
        kind: ConsentActionKind::Disclose,
        scope: requested_scope("age_over_18")?,
        derivation_id: None,
        derivation_inputs: Vec::new(),
    };
    let result = prepare_consent_request(
        &registered,
        requested_scope("age_over_18")?,
        vec![action],
        id("request-nonce-1")?,
        [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        timestamp(71)?,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateStale
    ));
    let backdated = prepare_consent_request(
        &registered,
        requested_scope("age_over_18")?,
        vec![ConsentAction {
            kind: ConsentActionKind::Disclose,
            scope: requested_scope("age_over_18")?,
            derivation_id: None,
            derivation_inputs: Vec::new(),
        }],
        id("request-nonce-2")?,
        [8; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        timestamp(9)?,
    );
    assert!(matches!(
        backdated,
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateStale
    ));
    assert!(matches!(
        validate_relying_party_registration_certificate(&validated, &policy(), timestamp(71)?),
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateStale
    ));
    Ok(())
}

#[test]
fn registration_rejects_a_different_or_unsupported_verified_client() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let validated = validate_registration_certificate_path(
        &chain,
        &validator("https://verifier.example")?,
        timestamp(10)?,
    )?;
    let registered = register_verifier_entitlement(&validated, &policy(), timestamp(10)?)?;
    for client_id in [
        "x509_san_dns:other.example",
        "redirect_uri:https://verifier.example",
    ] {
        let client = ClientIdentifier::parse(client_id)
            .map_err(|_| crate::ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
        let result = crate::capture::prepare_consent_request_for_client(
            &registered,
            &client,
            requested_scope("age_over_18")?,
            vec![ConsentAction {
                kind: ConsentActionKind::Disclose,
                scope: requested_scope("age_over_18")?,
                derivation_id: None,
                derivation_inputs: Vec::new(),
            }],
            crate::bind_verified_request::VerifiedRequestBinding {
                request_nonce: id("request-nonce-1")?,
                request_digest: [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
            },
            crate::UnregisteredAttributePolicy::WarnAndAllowAll,
            timestamp(11)?,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == ConsentErrorReason::ClientBindingMismatch
        ));
    }
    Ok(())
}

#[test]
fn registration_x509_hash_requires_a_verified_request_signer() -> Result<(), TestError> {
    let mut chain = chain_for_dns("verifier.example");
    chain.certs[0].der = b"registration-leaf-certificate".to_vec();
    let validated = validate_registration_certificate_path(
        &chain,
        &validator("https://verifier.example")?,
        timestamp(10)?,
    )?;
    let registered = register_verifier_entitlement(&validated, &policy(), timestamp(10)?)?;
    for der in [
        b"registration-leaf-certificate".as_slice(),
        b"different-leaf-certificate".as_slice(),
    ] {
        let digest = crypto_sha2_256::digest(der);
        let mut client_id = "x509_hash:".to_owned();
        client_id.push_str(&reallyme_codec::base64url::bytes_to_base64url(
            digest.as_bytes(),
        ));
        let client = ClientIdentifier::parse(&client_id)
            .map_err(|_| crate::ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
        let result = crate::capture::prepare_consent_request_for_client(
            &registered,
            &client,
            requested_scope("age_over_18")?,
            vec![ConsentAction {
                kind: ConsentActionKind::Disclose,
                scope: requested_scope("age_over_18")?,
                derivation_id: None,
                derivation_inputs: Vec::new(),
            }],
            crate::bind_verified_request::VerifiedRequestBinding {
                request_nonce: id("request-nonce-1")?,
                request_digest: [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
            },
            crate::UnregisteredAttributePolicy::WarnAndAllowAll,
            timestamp(11)?,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason == ConsentErrorReason::ClientBindingMismatch
        ));
    }
    Ok(())
}

#[test]
fn prepared_consent_rechecks_registration_freshness_at_capture() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let mut path_validator = validator("https://verifier.example")?;
    path_validator.entitlement.valid_until = timestamp(200)?;
    let validated =
        validate_registration_certificate_path(&chain, &path_validator, timestamp(10)?)?;
    let registered = register_verifier_entitlement(&validated, &policy(), timestamp(10)?)?;
    let action = ConsentAction {
        kind: ConsentActionKind::Disclose,
        scope: requested_scope("age_over_18")?,
        derivation_id: None,
        derivation_inputs: Vec::new(),
    };
    let prepared = prepare_consent_request(
        &registered,
        requested_scope("age_over_18")?,
        vec![action.clone()],
        id("request-nonce-1")?,
        [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        timestamp(11)?,
    )?;
    let capture = ConsentCapture {
        relying_party_id: registered.entitlement().relying_party_id.clone(),
        requested_scope: requested_scope("age_over_18")?,
        selected_action: action,
        request_nonce: id("request-nonce-1")?,
        request_digest: [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        policy_decision: DisclosurePolicyDecision::Allowed,
        user_decision: ConsentDecision::Approved,
        captured_at: timestamp(71)?,
    };
    let accepted_prepared = prepare_consent_request(
        &registered,
        requested_scope("age_over_18")?,
        vec![capture.selected_action.clone()],
        id("request-nonce-1")?,
        [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        timestamp(11)?,
    )?;
    let mut accepted_capture = capture.clone();
    accepted_capture.captured_at = timestamp(20)?;
    assert!(capture_prepared_consent(
        accepted_prepared,
        accepted_capture,
        &FixedClock(timestamp(20)?)
    )
    .is_ok());
    let regressed_prepared = prepare_consent_request(
        &registered,
        requested_scope("age_over_18")?,
        vec![capture.selected_action.clone()],
        id("request-nonce-1")?,
        [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        timestamp(11)?,
    )?;
    let mut regressed_capture = capture.clone();
    regressed_capture.captured_at = timestamp(9)?;
    assert!(matches!(
        capture_prepared_consent(
            regressed_prepared,
            regressed_capture,
            &FixedClock(timestamp(9)?)
        ),
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateStale
    ));
    assert!(matches!(
        capture_prepared_consent(prepared, capture, &FixedClock(timestamp(71)?)),
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateStale
    ));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("consent")]
    Consent(#[from] crate::ConsentError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}
