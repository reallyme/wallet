// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Relying-party registration and entitlement conformance tests.

use reallyme_trust_x509::{
    BasicConstraints, CertificatePolicyId, ExtendedKeyUsagePurpose, KeyUsage, PublicKeyProfile,
    QcStatementId, QcStatements, QcType, X509Certificate, X509Chain, X509Policy,
    OID_EKU_SERVER_AUTH, OID_ETSI_QCS_QC_COMPLIANCE, OID_ETSI_QCS_QC_TYPE, OID_ETSI_QCT_WEB,
    OID_QEVCP_W,
};
use reallyme_wallet::consent::{
    evaluate_registered_entitlement_at, validate_registration_certificate_path,
    validate_relying_party_registration_certificate, ConsentError, ConsentErrorReason,
    RegistrationCertificatePathError, RegistrationCertificatePathValidator,
};
use reallyme_wallet::types as wallet;
use time::{Duration, OffsetDateTime};

const NOW: i64 = 10;
const VALID_UNTIL: i64 = 20;

struct AcceptPathValidator {
    entitlement: wallet::VerifierEntitlement,
}

impl RegistrationCertificatePathValidator for AcceptPathValidator {
    fn validate_registration_certificate_path(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<wallet::VerifierEntitlement, RegistrationCertificatePathError> {
        Ok(self.entitlement.clone())
    }
}

#[test]
fn eudi_rp_registration_and_entitlement_allow_requested_scope() -> Result<(), TestError> {
    let chain = chain_for_dns("verifier.example");
    let validator = validator("https://verifier.example", &["age_over_18"])?;
    let validated = validate_registration_certificate_path(&chain, &validator, timestamp(NOW)?)?;
    let decision = evaluate_registered_entitlement_at(
        &requested_scope(&["age_over_18"])?,
        &validated,
        &policy(),
        timestamp(NOW)?,
    )?;

    assert_eq!(decision, wallet::DisclosurePolicyDecision::Allowed);
    Ok(())
}

#[test]
fn eudi_rp_registration_rejects_relying_party_mismatch() -> Result<(), TestError> {
    let chain = chain_for_dns("attacker.example");
    let validator = validator("https://verifier.example", &["age_over_18"])?;
    let validated = validate_registration_certificate_path(&chain, &validator, timestamp(NOW)?)?;
    let result =
        validate_relying_party_registration_certificate(&validated, &policy(), timestamp(NOW)?);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::RegistrationCertificateRelyingPartyMismatch
    ));
    Ok(())
}

#[test]
fn eudi_rp_entitlement_rejects_unauthorized_attribute_after_registration() -> Result<(), TestError>
{
    let chain = chain_for_dns("verifier.example");
    let validator = validator("https://verifier.example", &["age_over_18"])?;
    let validated = validate_registration_certificate_path(&chain, &validator, timestamp(NOW)?)?;
    let result = evaluate_registered_entitlement_at(
        &requested_scope(&["family_name"])?,
        &validated,
        &policy(),
        timestamp(NOW)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::AttributeNotAuthorized
    ));
    Ok(())
}

fn entitlement(
    relying_party_id: &str,
    authorized_attributes: &[&str],
) -> Result<wallet::VerifierEntitlement, TestError> {
    Ok(wallet::VerifierEntitlement {
        relying_party_id: id(relying_party_id)?,
        authorized_scope: requested_scope(authorized_attributes)?,
        valid_until: timestamp(VALID_UNTIL)?,
    })
}

fn validator(
    relying_party_id: &str,
    authorized_attributes: &[&str],
) -> Result<AcceptPathValidator, TestError> {
    Ok(AcceptPathValidator {
        entitlement: entitlement(relying_party_id, authorized_attributes)?,
    })
}

fn requested_scope(attributes: &[&str]) -> Result<wallet::ConsentScope, TestError> {
    let mut converted = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        converted.push(wallet::AttributeName::new((*attribute).to_owned())?);
    }

    Ok(wallet::ConsentScope {
        attributes: converted,
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
        subject_der: b"CN=verifier.example".to_vec(),
        issuer_der: b"CN=issuer.example".to_vec(),
        subject: "CN=verifier.example".to_owned(),
        issuer: "CN=issuer.example".to_owned(),
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
        subject_der: b"CN=issuer.example".to_vec(),
        issuer_der: b"CN=root.example".to_vec(),
        subject: "CN=issuer.example".to_owned(),
        issuer: "CN=root.example".to_owned(),
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

fn id(value: &str) -> Result<wallet::NonEmptyIdentifier, wallet::WalletTypesError> {
    wallet::NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<wallet::UnixTimestamp, wallet::WalletTypesError> {
    wallet::UnixTimestamp::from_seconds(seconds)
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("consent")]
    Consent(#[from] ConsentError),
    #[error("wallet_types")]
    WalletTypes(#[from] wallet::WalletTypesError),
}
