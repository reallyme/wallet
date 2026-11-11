// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0


#[test]
fn issuer_metadata_profile_enforces_etsi_registrar_structure() -> Result<(), TestError> {
    let mut metadata = issuer_metadata()?;
    assert_eq!(
        validate_issuer_metadata_profile(&metadata, OpenId4VciIssuerMetadataProfile::OpenId4Vci,),
        Ok(())
    );
    assert!(matches!(
        validate_issuer_metadata_profile(
            &metadata,
            OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3,
        ),
        Err(error) if error.reason == FlowErrorReason::InvalidIssuerMetadataProfile
    ));

    metadata.issuer_info = Some(vec![IssuerInformation {
        format: "registrar_dataset".to_owned(),
        data: json!({
            "identifier": {
                "type": "http://data.europa.eu/eudi/id/LEI",
                "identifier": "registered-provider-identifier"
            },
            "srvDescription": [{"lang": "en", "content": "Attestation issuance"}],
            "registryURI": "https://registrar.example/provider",
            "providesAttestations": []
        }),
    }]);
    assert_eq!(
        validate_issuer_metadata_profile(
            &metadata,
            OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3,
        ),
        Ok(())
    );
    assert!(matches!(
        validate_issuer_metadata_profile(
            &metadata,
            OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3,
        ),
        Err(error) if error.reason == FlowErrorReason::InvalidIssuerMetadataProfile
    ));

    metadata
        .issuer_info
        .as_mut()
        .ok_or(TestError::MissingCredentialRequest)?
        .push(IssuerInformation {
            format: "registration_cert".to_owned(),
            data: json!("opaque-profile-defined-registration-certificate"),
        });
    assert_eq!(
        validate_issuer_metadata_profile(
            &metadata,
            OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3,
        ),
        Ok(())
    );
    Ok(())
}

fn verified_etsi_metadata(
    signer_trust_purpose: SignedMetadataSignerTrustPurpose,
) -> Result<VerifiedSignedIssuerMetadata, TestError> {
    let header = json!({
        "alg": "ES256",
        "typ": "openidvci-issuer-metadata+jwt",
        "x5c": ["bGVhZi1hY2Nlc3MtY2VydGlmaWNhdGU="]
    });
    let claims = json!({
        "sub": "https://issuer.example",
        "iat": 1_700_000_000,
        "exp": 1_700_001_000,
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "issuer_info": [{
            "format": "registrar_dataset",
            "data": {
                "identifier": {
                    "type": "https://example.com/id",
                    "identifier": "issuer-1"
                },
                "srvDescription": [{"lang": "en", "content": "PID issuance"}],
                "registryURI": "https://registrar.example/issuer-1",
                "providesAttestations": []
            }
        }],
        "credential_configurations_supported": {
            "pid": {"format": "dc+sd-jwt", "vct": "https://example.com/pid"}
        }
    });
    let encoded_header =
        bytes_to_base64url(&serde_json::to_vec(&header).map_err(|_| TestError::Serde)?);
    let encoded_claims =
        bytes_to_base64url(&serde_json::to_vec(&claims).map_err(|_| TestError::Serde)?);
    let jwt = SignedIssuerMetadataJwt::new(format!("{encoded_header}.{encoded_claims}.AA"))?;
    verify_signed_issuer_metadata(
        &jwt,
        &SignedIssuerMetadataValidationContext {
            expected_credential_issuer: "https://issuer.example".to_owned(),
            current_time: 1_700_000_100,
            max_age_seconds: 300,
            allowed_clock_skew_seconds: 0,
            accepted_algorithms: vec![SignedMetadataAlgorithm::Es256],
            required_signer_trust_purpose: signer_trust_purpose,
        },
        &SignedMetadataTestVerifier {
            signer_trust_purpose,
        },
    )
    .map_err(TestError::from)
}

#[test]
fn etsi_profile_requires_access_certificate_trust_evidence() -> Result<(), TestError> {
    let generic =
        verified_etsi_metadata(SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner)?;
    let result = start_openid4vci_issuance_with_verified_metadata_profile(
        offer()?,
        &generic,
        OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        ReuseMethodSet::new(ReuseMethodSet::ONCE_ONLY)
            .map_err(|_| TestError::MissingCredentialRequest)?,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::InvalidIssuerMetadataProfile
    ));

    let access_certificate = verified_etsi_metadata(
        SignedMetadataSignerTrustPurpose::WalletRelyingPartyAccessCertificate,
    )?;
    let session = start_openid4vci_issuance_with_verified_metadata_profile(
        offer()?,
        &access_certificate,
        OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        ReuseMethodSet::new(ReuseMethodSet::ONCE_ONLY)
            .map_err(|_| TestError::MissingCredentialRequest)?,
    )?;
    assert_eq!(
        session.issuer_metadata_profile(),
        OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3
    );
    Ok(())
}

#[test]
fn selected_reuse_policy_retains_reissuance_thresholds() -> Result<(), TestError> {
    let mut metadata = issuer_metadata()?;
    let configuration = metadata
        .credential_configurations_supported
        .get_mut("pid")
        .ok_or(TestError::MissingCredentialRequest)?;
    configuration.credential_metadata = Some(json!({
        "credential_reuse_policy": {
            "id": "arf_annex_ii",
            "options": [{
                "details": ["once_only"],
                "batch_size": 4,
                "reissue_trigger_unused": 1
            }]
        }
    }));
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )?;
    let capabilities = ReuseMethodSet::new(ReuseMethodSet::ONCE_ONLY)
        .map_err(|_| TestError::MissingCredentialRequest)?;

    let session = start_openid4vci_issuance_with_reuse_capabilities(
        offer,
        &metadata,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
        capabilities,
    )?;

    assert_eq!(session.credential_reuse_policies().len(), 1);
    assert_eq!(
        session.credential_reuse_policies()[0].method(),
        CredentialReuseMethod::OnceOnly
    );
    assert_eq!(session.credential_reuse_policies()[0].batch_size(), Some(4));
    assert_eq!(
        session.credential_reuse_policies()[0].reissue_trigger_unused(),
        Some(1)
    );
    Ok(())
}
