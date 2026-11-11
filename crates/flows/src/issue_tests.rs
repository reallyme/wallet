// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_profiles::ReuseMethodSet;
use openid4vci_types::{
    build_credential_offer_uri, CredentialEnvelope, CredentialOffer, CredentialPayload,
    CredentialResponse, IssuerInformation, Proofs, TxCode, TxCodeInputMode,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid4vci_wallet::{
    verify_signed_issuer_metadata, CredentialOfferFetcher, CredentialOfferGrantType,
    ParsedSignedIssuerMetadata, SignedIssuerMetadataJwt, SignedIssuerMetadataTrustVerifier,
    SignedIssuerMetadataValidationContext, SignedMetadataAlgorithm,
    SignedMetadataSignerTrustPurpose, SignedMetadataTrustEvidenceInput, SignedMetadataTrustPurpose,
    TransactionCode, VerifiedSignedIssuerMetadata, WalletResult,
};
use reallyme_wallet_attestation::{
    verify_wallet_unit_attestation, AttestationResult, UnverifiedWalletUnitAttestation,
    WalletUnitAttestation, WalletUnitAttestationVerifier,
};
use reallyme_wallet_keystore::KeyAttestationEvidence;
use reallyme_wallet_types::{
    CredentialFormat, CredentialRecord, CredentialReuseMethod, CredentialStatus, EncryptedRecord,
    EncryptedRecordHeader, IssuerId, KeyHandleId, NonEmptyIdentifier,
    OpenId4VciIssuerMetadataProfile, SignedCredentialIssuer, UnixTimestamp, WalletTypesError,
};
use secrecy::SecretString;
use serde_json::json;
use std::{cell::RefCell, collections::VecDeque, sync::Mutex};

use crate::test_support::{
    issuer_metadata, prepared_credential_request, start_authorization_code_issuance,
    start_pre_authorized_code_issuance,
};

use super::validate_issuer_metadata_profile;
use crate::{
    bind_openid4vci_wallet_unit_attestation, build_openid4vci_pre_authorized_token_request,
    import_openid4vci_issued_credential as import_verified_credential,
    import_openid4vci_issued_credentials as import_verified_credentials,
    present_openid4vci_wallet_unit_attestation, record_openid4vci_authorized,
    record_openid4vci_consent,
    record_openid4vci_credential_request as record_verified_credential_request,
    record_openid4vci_credential_response, record_openid4vci_deferred_credential_response,
    record_openid4vci_token_exchanged, start_openid4vci_issuance_from_offer_uri,
    start_openid4vci_issuance_with_reuse_capabilities,
    start_openid4vci_issuance_with_verified_metadata_profile, CredentialProofBinding,
    CredentialRequestProofBinding, CredentialRequestProofVerifier, FlowErrorReason, FlowResult,
    IssuanceState, IssuedCredentialVerifier, OpenId4VciIssuanceSession,
    PreparedOpenId4VciCredentialRequest,
};

struct AcceptProofVerifier;

struct SignedMetadataTestVerifier {
    signer_trust_purpose: SignedMetadataSignerTrustPurpose,
}

impl SignedIssuerMetadataTrustVerifier for SignedMetadataTestVerifier {
    fn verify_signed_issuer_metadata(
        &self,
        _jwt: &SignedIssuerMetadataJwt,
        parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
        Ok(SignedMetadataTrustEvidenceInput {
            verified_signing_input: parsed.signing_input().to_owned(),
            signer_identity: "sha256:test-signer".to_owned(),
            asserted_issuer: None,
            policy_version: "test-policy-v1".to_owned(),
            source_snapshot: "test-snapshot-1".to_owned(),
            anchor: "test-anchor-1".to_owned(),
            evaluated_at: 1_700_000_100,
            valid_until: 1_700_000_700,
            purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
            signer_trust_purpose: self.signer_trust_purpose,
        })
    }
}

struct AttestationBatchProofVerifier;

impl CredentialRequestProofVerifier for AttestationBatchProofVerifier {
    fn verify_credential_request_proof(
        &self,
        request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        let proof_count = request
            .proofs
            .as_ref()
            .map(|proofs| proofs.attestation.len())
            .ok_or_else(|| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        if proof_count != 1 {
            return Err(crate::FlowError::new(
                FlowErrorReason::InvalidOpenId4VciState,
            ));
        }
        let mut proofs = Vec::with_capacity(2);
        for index in 0..2 {
            proofs.push(CredentialProofBinding {
                nonce_digest: None,
                audience: "https://issuer.example".to_owned(),
                holder_key_handle_id: credential_key_handle_id_at(index)?,
                issued_at: timestamp(15)
                    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            });
        }
        Ok(CredentialRequestProofBinding {
            proofs,
            wallet_unit_key_handle_id: key_handle_id()
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
        })
    }
}

impl CredentialRequestProofVerifier for AcceptProofVerifier {
    fn verify_credential_request_proof(
        &self,
        request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        let proof_count = request
            .proofs
            .as_ref()
            .map(|proofs| proofs.jwt.len())
            .ok_or_else(|| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        let mut proofs = Vec::with_capacity(proof_count);
        for index in 0..proof_count {
            proofs.push(CredentialProofBinding {
                nonce_digest: None,
                audience: "https://issuer.example".to_owned(),
                holder_key_handle_id: credential_key_handle_id_at(index)?,
                issued_at: timestamp(15)
                    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            });
        }
        Ok(CredentialRequestProofBinding {
            proofs,
            wallet_unit_key_handle_id: key_handle_id()
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
        })
    }
}

struct WrongWalletUnitProofVerifier;

struct SharedWalletUnitProofVerifier;

impl CredentialRequestProofVerifier for SharedWalletUnitProofVerifier {
    fn verify_credential_request_proof(
        &self,
        _request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        let key = key_handle_id()
            .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        Ok(CredentialRequestProofBinding {
            proofs: vec![CredentialProofBinding {
                nonce_digest: None,
                audience: "https://issuer.example".to_owned(),
                holder_key_handle_id: key.clone(),
                issued_at: timestamp(15)
                    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            }],
            wallet_unit_key_handle_id: key,
        })
    }
}

impl CredentialRequestProofVerifier for WrongWalletUnitProofVerifier {
    fn verify_credential_request_proof(
        &self,
        _request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        Ok(CredentialRequestProofBinding {
            proofs: vec![CredentialProofBinding {
                nonce_digest: None,
                audience: "https://issuer.example".to_owned(),
                holder_key_handle_id: credential_key_handle_id()
                    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
                issued_at: timestamp(15)
                    .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
            }],
            wallet_unit_key_handle_id: KeyHandleId::new("other-wallet-key".to_owned())
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
        })
    }
}

struct DuplicateCredentialKeyProofVerifier;

impl CredentialRequestProofVerifier for DuplicateCredentialKeyProofVerifier {
    fn verify_credential_request_proof(
        &self,
        _request: &openid4vci_types::CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding> {
        let holder_key_handle_id = credential_key_handle_id()
            .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        let issued_at = timestamp(15)
            .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
        Ok(CredentialRequestProofBinding {
            proofs: vec![
                CredentialProofBinding {
                    nonce_digest: None,
                    audience: "https://issuer.example".to_owned(),
                    holder_key_handle_id: holder_key_handle_id.clone(),
                    issued_at,
                },
                CredentialProofBinding {
                    nonce_digest: None,
                    audience: "https://issuer.example".to_owned(),
                    holder_key_handle_id,
                    issued_at,
                },
            ],
            wallet_unit_key_handle_id: key_handle_id()
                .map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?,
        })
    }
}

struct RecordVerifier {
    records: RefCell<VecDeque<CredentialRecord>>,
}

impl IssuedCredentialVerifier for RecordVerifier {
    fn verify_issued_credential(
        &self,
        _envelope: &CredentialEnvelope,
        _expected_credential_issuer: &IssuerId,
        _expected_holder_keys: &[KeyHandleId],
        _received_at: UnixTimestamp,
    ) -> FlowResult<CredentialRecord> {
        self.records
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| crate::FlowError::new(FlowErrorReason::InvalidCredentialReceipt))
    }
}

struct StaticOfferFetcher {
    offer: Mutex<Option<CredentialOffer>>,
}

impl CredentialOfferFetcher for StaticOfferFetcher {
    fn fetch_offer(&self, _credential_offer_uri: &str) -> WalletResult<CredentialOffer> {
        self.offer
            .lock()
            .map_err(|_| {
                reallyme_openid4vci_wallet::WalletError::new(
                    reallyme_openid4vci_wallet::WalletStatus::InvalidRequest,
                )
            })?
            .take()
            .ok_or_else(|| {
                reallyme_openid4vci_wallet::WalletError::new(
                    reallyme_openid4vci_wallet::WalletStatus::InvalidRequest,
                )
            })
    }
}

fn offer() -> openid4vci_types::OpenId4VciResult<CredentialOffer> {
    CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
}

fn request() -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    prepared_credential_request(
        Some(Proofs {
            jwt: vec!["proof-1".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
    )
}

fn batch_request() -> FlowResult<PreparedOpenId4VciCredentialRequest> {
    prepared_credential_request(
        Some(Proofs {
            jwt: vec!["proof-1".to_owned(), "proof-2".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
    )
}

fn pre_authorized_offer() -> openid4vci_types::OpenId4VciResult<CredentialOffer> {
    CredentialOffer::pre_authorized_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        "code-123".to_owned(),
        Some(TxCode {
            input_mode: Some(TxCodeInputMode::Numeric),
            length: Some(6),
            description: Some("Issuer-provided transaction code".to_owned()),
        }),
    )
}

fn transaction_code(value: &str) -> reallyme_openid4vci_wallet::WalletResult<TransactionCode> {
    TransactionCode::new(SecretString::from(value.to_owned()))
}

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn key_handle_id() -> Result<KeyHandleId, WalletTypesError> {
    KeyHandleId::new("key-1".to_owned())
}

fn credential_key_handle_id() -> Result<KeyHandleId, WalletTypesError> {
    KeyHandleId::new("credential-key-1".to_owned())
}

fn second_credential_key_handle_id() -> Result<KeyHandleId, WalletTypesError> {
    KeyHandleId::new("credential-key-2".to_owned())
}

fn credential_key_handle_id_at(index: usize) -> FlowResult<KeyHandleId> {
    let result = match index {
        0 => credential_key_handle_id(),
        1 => second_credential_key_handle_id(),
        _ => {
            return Err(crate::FlowError::new(
                FlowErrorReason::InvalidOpenId4VciState,
            ))
        }
    };
    result.map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))
}

fn record_openid4vci_credential_request(
    session: OpenId4VciIssuanceSession,
    request: &PreparedOpenId4VciCredentialRequest,
    now: UnixTimestamp,
) -> FlowResult<OpenId4VciIssuanceSession> {
    record_verified_credential_request(session, request, now, &AcceptProofVerifier)
}

fn import_openid4vci_issued_credential(
    session: OpenId4VciIssuanceSession,
    record: CredentialRecord,
) -> FlowResult<(OpenId4VciIssuanceSession, CredentialRecord)> {
    let verifier = RecordVerifier {
        records: RefCell::new(VecDeque::from([record])),
    };
    import_verified_credential(session, timestamp_for_flow(16)?, &verifier)
}

fn import_openid4vci_issued_credentials(
    session: OpenId4VciIssuanceSession,
    records: Vec<CredentialRecord>,
) -> FlowResult<(OpenId4VciIssuanceSession, Vec<CredentialRecord>)> {
    let verifier = RecordVerifier {
        records: RefCell::new(records.into()),
    };
    import_verified_credentials(session, timestamp_for_flow(16)?, &verifier)
}

fn timestamp_for_flow(seconds: i64) -> FlowResult<UnixTimestamp> {
    timestamp(seconds).map_err(|_| crate::FlowError::new(FlowErrorReason::InvalidCredentialReceipt))
}

struct AcceptAttestationVerifier;

impl WalletUnitAttestationVerifier for AcceptAttestationVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _attestation: &UnverifiedWalletUnitAttestation,
        _now: UnixTimestamp,
    ) -> AttestationResult<reallyme_wallet_attestation::VerifiedWalletKeyThumbprint> {
        reallyme_wallet_attestation::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

fn attestation(valid_until: i64) -> Result<WalletUnitAttestation, TestError> {
    let unverified = UnverifiedWalletUnitAttestation::new(
        id("wua-1")?,
        KeyAttestationEvidence {
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            evidence: vec![1, 2, 3],
            issued_at: timestamp(10)?,
            challenge: [7; 32],
        },
        timestamp(valid_until)?,
        vec![9, 8, 7],
    )?;
    Ok(verify_wallet_unit_attestation(
        unverified,
        &AcceptAttestationVerifier,
        timestamp(10)?,
    )?)
}

fn encrypted_record() -> Result<EncryptedRecord, WalletTypesError> {
    Ok(EncryptedRecord {
        header: EncryptedRecordHeader {
            schema_version: 1,
            key_handle_id: reallyme_wallet_types::KeyHandleId::new("key-1".to_owned())?,
            algorithm: reallyme_wallet_types::StorageEncryptionAlgorithm::Aes256GcmSiv,
            created_at: timestamp(16)?,
        },
        nonce: vec![1; 12],
        aad: vec![2],
        ciphertext: vec![3; 16],
    })
}

fn credential_record(status: CredentialStatus) -> Result<CredentialRecord, WalletTypesError> {
    Ok(CredentialRecord::new(
        id("credential-1")?,
        id("https://issuer.example")?,
        Some(SignedCredentialIssuer::new(
            "https://issuer.example".to_owned(),
        )?),
        Some(credential_key_handle_id()?),
        None,
        CredentialFormat::SdJwtVc,
        status,
        timestamp(16)?,
        encrypted_record()?,
    ))
}

fn authorized_session_with_attestation() -> Result<OpenId4VciIssuanceSession, TestError> {
    let session = start_authorization_code_issuance(offer()?)?;
    let session = record_openid4vci_consent(
        session,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    let session =
        bind_openid4vci_wallet_unit_attestation(session, attestation(20)?, timestamp(15)?)?;
    Ok(record_openid4vci_authorized(session)?)
}

fn token_exchanged_session_with_attestation() -> Result<OpenId4VciIssuanceSession, TestError> {
    let session = authorized_session_with_attestation()?;
    Ok(record_openid4vci_token_exchanged(
        session,
        NonEmptyIdentifier::new("token-handle-1".to_owned())?,
    )?)
}

#[test]
fn issuance_consent_requires_an_explicit_approved_host_decision() -> Result<(), TestError> {
    struct DecliningProvider {
        calls: usize,
    }

    impl crate::IssuanceConsentProvider for DecliningProvider {
        fn capture_issuance_consent(
            &mut self,
            request: crate::IssuanceConsentRequest<'_>,
        ) -> FlowResult<crate::IssuanceConsentDecision> {
            self.calls = self
                .calls
                .checked_add(1)
                .ok_or_else(|| crate::FlowError::new(FlowErrorReason::InvalidOpenId4VciState))?;
            assert_eq!(request.credential_issuer(), "https://issuer.example");
            assert_eq!(request.credential_configuration_ids(), ["pid"]);
            assert_eq!(
                request.grant_type(),
                reallyme_openid4vci_wallet::CredentialOfferGrantType::AuthorizationCode
            );
            Ok(crate::IssuanceConsentDecision::Rejected)
        }
    }

    let mut provider = DecliningProvider { calls: 0 };
    let session = start_authorization_code_issuance(offer()?)?;
    assert!(matches!(
        record_openid4vci_consent(session, &mut provider),
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    assert_eq!(provider.calls, 1);

    let approved = record_openid4vci_consent(
        start_authorization_code_issuance(offer()?)?,
        &mut crate::test_support::ApprovedIssuanceConsentProvider,
    )?;
    assert!(matches!(approved.state(), IssuanceState::ConsentCaptured));
    assert!(matches!(
        record_openid4vci_consent(approved, &mut provider),
        Err(error) if error.reason == FlowErrorReason::InvalidTransition
    ));
    assert_eq!(provider.calls, 1);
    Ok(())
}

#[test]
fn starts_issuance_from_inline_offer_uri() -> Result<(), TestError> {
    let offer = offer()?;
    let uri = build_credential_offer_uri("openid-credential-offer://", &offer.to_json()?)?;

    let session = start_openid4vci_issuance_from_offer_uri(
        &uri,
        None,
        &issuer_metadata()?,
        reallyme_openid4vci_wallet::CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;

    assert!(matches!(session.state, IssuanceState::OfferReceived));
    assert_eq!(session.credential_issuer(), "https://issuer.example");
    Ok(())
}

#[test]
fn derives_authorization_resource_only_from_explicit_issuer_metadata() -> Result<(), TestError> {
    let credential_offer = || {
        CredentialOffer::authorization_code(
            "https://issuer.example".to_owned(),
            vec!["pid".to_owned()],
            None,
        )
    };

    let implicit = crate::start_openid4vci_issuance(
        credential_offer()?,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;
    assert_eq!(implicit.authorization_request_resource(), None);

    let mut same_server_metadata = issuer_metadata()?;
    same_server_metadata.authorization_servers = Some(vec!["https://issuer.example".to_owned()]);
    let same_server = crate::start_openid4vci_issuance(
        credential_offer()?,
        &same_server_metadata,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;
    assert_eq!(
        same_server.authorization_request_resource(),
        Some("https://issuer.example")
    );

    let mut split_server_metadata = issuer_metadata()?;
    split_server_metadata.authorization_servers = Some(vec!["https://as.example".to_owned()]);
    let split_server = crate::start_openid4vci_issuance(
        credential_offer()?,
        &split_server_metadata,
        CredentialOfferGrantType::AuthorizationCode,
        "https://as.example".to_owned(),
    )?;
    assert_eq!(
        split_server.authorization_request_resource(),
        Some("https://issuer.example")
    );
    Ok(())
}

#[test]
fn starts_issuance_from_referenced_offer_uri_with_fetcher() -> Result<(), TestError> {
    let fetcher = StaticOfferFetcher {
        offer: Mutex::new(Some(offer()?)),
    };

    let session = start_openid4vci_issuance_from_offer_uri(
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
        Some(&fetcher),
        &issuer_metadata()?,
        reallyme_openid4vci_wallet::CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;

    assert_eq!(session.credential_configuration_ids(), ["pid".to_owned()]);
    Ok(())
}

#[test]
fn referenced_offer_uri_without_fetcher_fails_closed() -> Result<(), TestError> {
    let result = start_openid4vci_issuance_from_offer_uri(
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
        None,
        &issuer_metadata()?,
        reallyme_openid4vci_wallet::CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == FlowErrorReason::CredentialOfferResolutionRequired
    ));
    Ok(())
}

include!("issue_session_tests.rs");

include!("issue_profile_tests.rs");

include!("issue_deferred_tests.rs");

include!("issue_import_tests.rs");

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("flow")]
    Flow(#[from] crate::FlowError),
    #[error("openid4vci")]
    OpenId4Vci(#[from] openid4vci_types::OpenId4VciError),
    #[error("reallyme_openid4vci_wallet")]
    Wallet(#[from] reallyme_openid4vci_wallet::WalletError),
    #[error("serde")]
    Serde,
    #[error("wallet_types")]
    WalletTypes(#[from] reallyme_wallet_types::WalletTypesError),
    #[error("attestation")]
    Attestation(#[from] reallyme_wallet_attestation::AttestationError),
    #[error("missing_credential_request")]
    MissingCredentialRequest,
}
