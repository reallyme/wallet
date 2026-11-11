// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::{
    capture_prepared_consent, capture_receipt_consent, prepare_consent_request,
    prepare_online_receipt_consent, register_verified_registration_authorization,
    ConsentCaptureStore, ConsentCaptureStoreError, ConsentCaptureStoreErrorReason, ConsentClaim,
    ConsentErrorReason, PreparedConsentRequest, RegistrationAuthorizationError,
    RegistrationAuthorizationFailureReason, RegistrationAuthorizationSource,
    RegistrationAuthorizationVerifier, TrustedConsentClock, UnregisteredAttributePolicy,
    VerifiedRegistrationAuthorization,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid4vp_types::AuthorizationRequestObject;
use reallyme_openid4vp_wallet::{
    verify_signed_request_object, BoundedX509CertificateChain, JoseRequestObjectVerification,
    JoseRequestObjectVerificationResolver, JoseSignedRequestObjectVerifier,
    TrustedX509RequestObjectSigner, VerifiedPlatformOrigin, VerifiedWalletRequest,
    WalletAuthorizationRequest, WalletError, WalletErrorReason, WalletInvocationContext,
    X509RequestObjectTrustDecision, X509TrustDecisionContext,
};
use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision,
    ConsentReceipt, ConsentScope, NonEmptyIdentifier, UnixTimestamp, VerifierEntitlement,
};
use std::collections::BTreeSet;
const SECRET: [u8; 32] = [7; 32];
fn time(n: i64) -> UnixTimestamp {
    UnixTimestamp::from_seconds(n).expect("test time")
}
fn scope() -> ConsentScope {
    ConsentScope {
        attributes: vec![AttributeName::new("age".into()).expect("test attribute")],
    }
}
struct Clock(i64);
impl TrustedConsentClock for Clock {
    fn now(&self) -> UnixTimestamp {
        time(self.0)
    }
}
fn key() -> (Vec<u8>, reallyme_jose::Jwk) {
    let (public, _) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&SECRET).expect("test key");
    let jwk = reallyme_crypto::jwk::p256_public_key_to_jwk(
        &public,
        reallyme_crypto::jwk::JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("test-key".into()),
        },
    )
    .expect("test JWK");
    (
        public,
        serde_json::from_value(
            serde_json::to_value(reallyme_crypto::jwk::Jwk::Ec(jwk)).expect("test JWK encodes"),
        )
        .expect("test JWK decodes"),
    )
}
struct Resolver;
impl JoseRequestObjectVerificationResolver for Resolver {
    fn resolve_request_object_verification(
        &self,
        _: &str,
        _: Option<&reallyme_openid4vp_types::ClientIdentifier>,
        chain: Option<&BoundedX509CertificateChain>,
        _: u64,
    ) -> Result<JoseRequestObjectVerification, WalletError> {
        let (public, jwk) = key();
        let context = X509TrustDecisionContext::new(1, [1; 32], [2; 32], 10, 100)?;
        // The trust provider is a fixture; the published JOSE boundary still
        // checks the real signature, certificate digest, key and request.
        let signer = TrustedX509RequestObjectSigner::new(
            chain
                .cloned()
                .ok_or_else(|| WalletError::new(WalletErrorReason::MissingX509CertificateChain))?,
            public.clone(),
            vec![],
            context,
        )?;
        Ok(JoseRequestObjectVerification::new(jwk, public)
            .with_x509_trust_decision(X509RequestObjectTrustDecision::Trusted(signer)))
    }
}
fn request(state: &str) -> AuthorizationRequestObject {
    let hash = bytes_to_base64url(&crypto_sha2_256::digest(b"test").into_bytes());
    let client = format!("x509_hash:{hash}");
    serde_json::from_value(serde_json::json!({
        "client_id": client, "iss": client, "aud": ["wallet"],
        "response_type": "vp_token", "response_mode": "dc_api.jwt",
        "nonce": "verifier-nonce-1", "state": state, "iat": 10, "exp": 30,
        "expected_origins": ["https://rp.example"],
        "dcql_query": {"credentials": [{"id":"pid", "format":"mso_mdoc", "meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}
    })).expect("test request validates")
}
fn signed(state: &str) -> String {
    let protected = bytes_to_base64url(
        &serde_json::to_vec(&serde_json::json!({
            "alg":"ES256", "typ":"oauth-authz-req+jwt", "kid":"test-key", "x5c":["dGVzdA=="]
        }))
        .expect("test header"),
    );
    let payload = bytes_to_base64url(&serde_json::to_vec(&request(state)).expect("test payload"));
    let input = format!("{protected}.{payload}");
    let signature =
        reallyme_jose::jws::suites::es256::sign_p256_jose_prehash(&SECRET, input.as_bytes())
            .expect("test signature");
    format!("{input}.{}", bytes_to_base64url(&signature))
}
fn verified(state: &str) -> VerifiedWalletRequest {
    verify_signed_request_object(
        &JoseSignedRequestObjectVerifier::new(Resolver, "wallet".into()),
        &signed(state),
        &WalletInvocationContext::DigitalCredentialsApi(
            VerifiedPlatformOrigin::from_browser_security_context("https://rp.example".into())
                .expect("test origin"),
        ),
        11,
    )
    .expect("public signed verification succeeds")
}
struct Registrar;
impl RegistrationAuthorizationVerifier for Registrar {
    fn verify_registration_authorization(
        &self,
        request: &VerifiedWalletRequest,
        _: UnixTimestamp,
    ) -> Result<VerifiedRegistrationAuthorization, RegistrationAuthorizationError> {
        VerifiedRegistrationAuthorization::new(
            VerifierEntitlement {
                relying_party_id: NonEmptyIdentifier::new("https://rp.example".into())
                    .expect("test RP"),
                authorized_scope: scope(),
                valid_until: time(100),
            },
            request
                .request()
                .client_id
                .clone()
                .expect("verified client"),
            *request
                .x509_request_signer()
                .expect("verified signer")
                .leaf_certificate_sha256(),
            time(10),
            time(40),
            RegistrationAuthorizationSource::RegistrarRecord,
        )
        .map_err(|_| {
            RegistrationAuthorizationError::new(
                RegistrationAuthorizationFailureReason::InvalidProof,
            )
        })
    }
}
fn prepared(request: &VerifiedWalletRequest) -> PreparedConsentRequest {
    let registered = register_verified_registration_authorization(&Registrar, request, time(11))
        .expect("registered signer");
    prepare_consent_request(
        &registered,
        request,
        scope(),
        vec![ConsentAction {
            kind: ConsentActionKind::Disclose,
            scope: scope(),
            derivation_id: None,
            derivation_inputs: vec![],
        }],
        UnregisteredAttributePolicy::RejectRequest,
        time(11),
    )
    .expect("public consent preparation")
}
fn decision(prepared: &PreparedConsentRequest, now: i64) -> ConsentCapture {
    let r = prepared.request();
    ConsentCapture {
        relying_party_id: r.relying_party_id.clone(),
        requested_scope: r.requested_scope.clone(),
        selected_action: r.actions[0].clone(),
        request_nonce: r.request_nonce.clone(),
        request_digest: r.request_digest,
        policy_decision: r.policy_decision,
        user_decision: ConsentDecision::Approved,
        captured_at: time(now),
    }
}
#[derive(Default)]
struct Store(BTreeSet<(String, String)>, Vec<ConsentReceipt>);
impl ConsentCaptureStore for Store {
    fn claim_capture(
        &mut self,
        claim: &ConsentClaim<'_>,
        receipt: Option<&ConsentReceipt>,
    ) -> Result<(), ConsentCaptureStoreError> {
        assert!(claim.namespace.as_str().starts_with("client-sha256:"));
        assert_eq!(claim.relying_party_id.as_str(), "https://rp.example");
        assert_eq!(claim.retain_until, time(30));
        if !self.0.insert((
            claim.namespace.as_str().into(),
            claim.request_nonce.as_str().into(),
        )) {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::AlreadyClaimed,
            ));
        }
        if let Some(receipt) = receipt {
            self.1.push(receipt.clone());
        }
        Ok(())
    }
}
#[test]
fn real_verified_request_reaches_public_consent_and_final_authorization() {
    let v = verified("state-1");
    let p = prepared(&v);
    assert_eq!(p.request().request_nonce.as_str(), "verifier-nonce-1");
    let c = decision(&p, 12);
    let captured = capture_prepared_consent(p, c, &Clock(12), &mut Store::default())
        .expect("capture succeeds");
    let authorized = captured
        .authorize_final_disclosure(&v, scope(), &Clock(13))
        .expect("final disclosure succeeds");
    assert_eq!(authorized.valid_until(), time(30));
}
#[test]
fn verified_request_change_cannot_inherit_the_capture() {
    let v = verified("state-1");
    let p = prepared(&v);
    let c = decision(&p, 12);
    let captured = capture_prepared_consent(p, c, &Clock(12), &mut Store::default())
        .expect("capture succeeds");
    let changed = verified("state-2");
    assert!(
        matches!(captured.authorize_final_disclosure(&changed,scope(),&Clock(13)),Err(e) if e.reason==ConsentErrorReason::RequestBindingMismatch)
    );
}
#[test]
fn real_request_expiry_is_checked_before_capture_store() {
    let v = verified("state-1");
    let p = prepared(&v);
    let c = decision(&p, 30);
    let mut store = Store::default();
    assert!(
        matches!(capture_prepared_consent(p,c,&Clock(30),&mut store),Err(e) if e.reason==ConsentErrorReason::RequestExpired)
    );
    assert!(store.0.is_empty());
}
#[test]
fn both_public_capture_forms_share_the_signed_verifier_nonce() {
    for receipt_first in [true, false] {
        let v = verified("state-1");
        let mut store = Store::default();
        for second in [false, true] {
            let p = prepared(&v);
            let c = decision(&p, 12);
            let result = if receipt_first != second {
                let p = prepare_online_receipt_consent(p);
                let digest = *p.context_digest();
                capture_receipt_consent(p, c, digest, None, &Clock(12), &mut store).map(|_| ())
            } else {
                capture_prepared_consent(p, c, &Clock(12), &mut store).map(|_| ())
            };
            if second {
                assert!(
                    matches!(result,Err(e) if e.reason==ConsentErrorReason::CaptureAlreadyUsed)
                );
            } else {
                result.expect("first capture succeeds");
            }
        }
        assert_eq!(store.0.len(), 1);
        assert_eq!(store.1.len(), usize::from(receipt_first));
    }
}
