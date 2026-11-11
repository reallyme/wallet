// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bind_receipt_policy, capture_receipt_consent, consent_policy_digest,
    prepare_reader_receipt_consent, ConsentPolicyVerifier, PolicyContextAuthorization,
    PreparedReceiptConsent, ReaderAuthorizationFacts, ReaderAuthorizationVerifier,
};
use crate::{ConsentError, ConsentErrorReason, ConsentResult, TrustedConsentClock};
use reallyme_wallet_storage::{
    ConsentCaptureStore, ConsentCaptureStoreError, ConsentCaptureStoreErrorReason,
};
use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision,
    ConsentPolicyChoice, ConsentPolicyContext, ConsentReceipt, ConsentRetention, ConsentScope,
    NonEmptyIdentifier, ReaderSessionBinding, RelyingPartyId, UnixTimestamp, VerifierEntitlement,
    WalletTypesError,
};
use thiserror::Error;
struct Reader;
struct OverAskingReader;
impl ReaderAuthorizationVerifier for OverAskingReader {
    type Evidence = ();
    fn verify_reader(&self, _: &(), _: UnixTimestamp) -> ConsentResult<ReaderAuthorizationFacts> {
        let mut facts = facts()
            .map_err(|_| ConsentError::new(ConsentErrorReason::ReaderAuthenticationRejected))?;
        facts
            .requested_scope
            .attributes
            .push(AttributeName::new("portrait".into()).map_err(|_| {
                ConsentError::new(ConsentErrorReason::ReaderAuthenticationRejected)
            })?);
        Ok(facts)
    }
}
fn time(n: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(n)
}
fn rp() -> Result<RelyingPartyId, WalletTypesError> {
    RelyingPartyId::new("https://reader.example".into())
}
fn scope() -> Result<ConsentScope, WalletTypesError> {
    Ok(ConsentScope {
        attributes: vec![AttributeName::new("age".into())?],
    })
}
impl ReaderAuthorizationVerifier for Reader {
    type Evidence = bool;
    fn verify_reader(
        &self,
        evidence: &bool,
        _: UnixTimestamp,
    ) -> ConsentResult<ReaderAuthorizationFacts> {
        if !evidence {
            return Err(ConsentError::new(
                ConsentErrorReason::ReaderAuthenticationRejected,
            ));
        }
        facts().map_err(|_| ConsentError::new(ConsentErrorReason::ReaderAuthenticationRejected))
    }
}
fn facts() -> Result<ReaderAuthorizationFacts, WalletTypesError> {
    Ok(ReaderAuthorizationFacts {
        binding: ReaderSessionBinding {
            reader_id: rp()?,
            certificate_digest: [1; 32],
            session_digest: [2; 32],
            request_digest: [3; 32],
            authenticated_at: time(10)?,
            valid_until: time(100)?,
        },
        entitlement: VerifierEntitlement {
            relying_party_id: rp()?,
            authorized_scope: scope()?,
            valid_until: time(100)?,
        },
        requested_scope: scope()?,
        request_nonce: NonEmptyIdentifier::new("nonce".into())?,
    })
}
struct Policy(bool);
impl ConsentPolicyVerifier for Policy {
    fn verify_policy_context(
        &self,
        request: &reallyme_wallet_types::ConsentRequest,
        context: &ConsentPolicyContext,
        now: UnixTimestamp,
    ) -> ConsentResult<PolicyContextAuthorization> {
        if !self.0 {
            return Err(ConsentError::new(ConsentErrorReason::PolicyUnsupported));
        }
        Ok(PolicyContextAuthorization {
            relying_party_id: request.relying_party_id.clone(),
            request_digest: request.request_digest,
            policy_digest: consent_policy_digest(context)?,
            verified_at: now,
            valid_until: time(90)
                .map_err(|_| ConsentError::new(ConsentErrorReason::PolicyContextMismatch))?,
        })
    }
}
struct Clock(UnixTimestamp);
impl TrustedConsentClock for Clock {
    fn now(&self) -> UnixTimestamp {
        self.0
    }
}
#[derive(Default)]
struct Store {
    receipts: Vec<ConsentReceipt>,
    claims: std::collections::BTreeSet<(String, String)>,
    fail: bool,
}
impl ConsentCaptureStore for Store {
    fn claim_capture(
        &mut self,
        claim: &crate::ConsentClaim<'_>,
        receipt: Option<&ConsentReceipt>,
    ) -> Result<(), ConsentCaptureStoreError> {
        if self.fail {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::Unavailable,
            ));
        }
        if !self.claims.insert((
            claim.namespace.as_str().to_owned(),
            claim.request_nonce.as_str().to_owned(),
        )) {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::AlreadyClaimed,
            ));
        }
        if let Some(receipt) = receipt {
            self.receipts.push(receipt.clone());
        }
        Ok(())
    }
}
fn prepared() -> Result<PreparedReceiptConsent, TestError> {
    Ok(prepare_reader_receipt_consent(
        &Reader,
        &true,
        vec![ConsentAction {
            kind: ConsentActionKind::Disclose,
            scope: scope()?,
            derivation_id: None,
            derivation_inputs: vec![],
        }],
        crate::UnregisteredAttributePolicy::WarnAndAllowAll,
        time(20)?,
    )?)
}
fn context() -> Result<ConsentPolicyContext, WalletTypesError> {
    Ok(ConsentPolicyContext {
        purpose: NonEmptyIdentifier::new("age-check".into())?,
        retention: ConsentRetention::NoRetention,
        policies: vec![ConsentPolicyChoice {
            id: NonEmptyIdentifier::new("terms".into())?,
            version: NonEmptyIdentifier::new("1".into())?,
            document_digest: [5; 32],
            mandatory: true,
            accepted: true,
        }],
        transaction_digest: [6; 32],
    })
}
fn capture(p: &PreparedReceiptConsent) -> ConsentCapture {
    let r = p.request();
    ConsentCapture {
        relying_party_id: r.relying_party_id.clone(),
        requested_scope: r.requested_scope.clone(),
        selected_action: r.actions[0].clone(),
        request_nonce: r.request_nonce.clone(),
        request_digest: r.request_digest,
        policy_decision: r.policy_decision,
        user_decision: ConsentDecision::Approved,
        captured_at: r.created_at,
    }
}
#[test]
fn authentic_reader_policy_receipt_and_final_scope_are_bound() -> Result<(), TestError> {
    let p = bind_receipt_policy(prepared()?, context()?, &Policy(true), time(20)?)?;
    let c = capture(&p);
    let digest = *p.context_digest();
    let reader = p.reader().cloned();
    let mut store = Store::default();
    let cap =
        capture_receipt_consent(p, c, digest, reader.as_ref(), &Clock(time(20)?), &mut store)?;
    assert_eq!(store.receipts.len(), 1);
    assert!(cap.receipt().policy.is_some());
    let final_cap = cap.authorize_final_disclosure(None, scope()?, digest, &Clock(time(20)?))?;
    assert!(final_cap.receipt().reader.is_some());
    Ok(())
}
#[test]
fn changed_reader_session_and_policy_context_cannot_authorize() -> Result<(), TestError> {
    for changed_session in [true, false] {
        let p = prepared()?;
        let c = capture(&p);
        let mut digest = *p.context_digest();
        let mut reader = p.reader().cloned();
        if changed_session {
            if let Some(r) = &mut reader {
                r.session_digest = [9; 32];
            }
        } else {
            digest = [9; 32];
        }
        let mut store = Store::default();
        assert!(capture_receipt_consent(
            p,
            c,
            digest,
            reader.as_ref(),
            &Clock(time(20)?),
            &mut store
        )
        .is_err());
        assert!(store.receipts.is_empty());
    }
    Ok(())
}
#[test]
fn policy_mutations_change_digest_and_mandatory_unsupported_fails() -> Result<(), TestError> {
    let ctx = context()?;
    let digest = consent_policy_digest(&ctx)?;
    let mut changed = ctx.clone();
    changed.retention = ConsentRetention::Until(time(80)?);
    assert_ne!(consent_policy_digest(&changed)?, digest);
    changed = ctx.clone();
    changed.purpose = NonEmptyIdentifier::new("another-purpose".into())?;
    assert_ne!(consent_policy_digest(&changed)?, digest);
    changed = ctx.clone();
    changed.policies[0].version = NonEmptyIdentifier::new("2".into())?;
    assert_ne!(consent_policy_digest(&changed)?, digest);
    changed = ctx.clone();
    changed.transaction_digest = [9; 32];
    assert_ne!(consent_policy_digest(&changed)?, digest);
    changed = ctx;
    changed.policies[0].accepted = false;
    assert!(consent_policy_digest(&changed).is_err());
    assert!(
        matches!(bind_receipt_policy(prepared()?,context()?,&Policy(false),time(20)?),Err(e) if e.reason==ConsentErrorReason::PolicyUnsupported)
    );
    Ok(())
}
#[test]
fn replay_refusal_expiry_extra_disclosure_and_failed_append_fail_closed() -> Result<(), TestError> {
    let mut store = Store::default();
    for repeat in 0..2 {
        let p = prepared()?;
        let c = capture(&p);
        let digest = *p.context_digest();
        let reader = p.reader().cloned();
        let result =
            capture_receipt_consent(p, c, digest, reader.as_ref(), &Clock(time(20)?), &mut store);
        if repeat == 0 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
    assert_eq!(store.receipts.len(), 1);
    for rejected in [true, false] {
        let p = prepared()?;
        let mut c = capture(&p);
        let digest = *p.context_digest();
        let reader = p.reader().cloned();
        let now = if rejected {
            c.user_decision = ConsentDecision::Rejected;
            20
        } else {
            100
        };
        assert!(capture_receipt_consent(
            p,
            c,
            digest,
            reader.as_ref(),
            &Clock(time(now)?),
            &mut Store::default()
        )
        .is_err());
    }
    let p = prepared()?;
    let c = capture(&p);
    let d = *p.context_digest();
    let reader = p.reader().cloned();
    let cap = capture_receipt_consent(
        p,
        c,
        d,
        reader.as_ref(),
        &Clock(time(20)?),
        &mut Store::default(),
    )?;
    assert!(cap
        .authorize_final_disclosure(
            None,
            ConsentScope {
                attributes: vec![AttributeName::new("extra".into())?]
            },
            d,
            &Clock(time(20)?)
        )
        .is_err());
    let p = prepared()?;
    let c = capture(&p);
    let d = *p.context_digest();
    let reader = p.reader().cloned();
    let mut failing = Store {
        fail: true,
        ..Store::default()
    };
    assert!(
        capture_receipt_consent(p, c, d, reader.as_ref(), &Clock(time(20)?), &mut failing).is_err()
    );
    assert!(failing.receipts.is_empty());
    Ok(())
}
#[derive(Debug, Error)]
enum TestError {
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("consent")]
    Consent(#[from] ConsentError),
}

#[test]
fn final_disclosure_rechecks_trusted_time_after_holder_approval() -> Result<(), TestError> {
    let p = bind_receipt_policy(prepared()?, context()?, &Policy(true), time(20)?)?;
    let c = capture(&p);
    let digest = *p.context_digest();
    let reader = p.reader().cloned();
    let cap = capture_receipt_consent(
        p,
        c,
        digest,
        reader.as_ref(),
        &Clock(time(20)?),
        &mut Store::default(),
    )?;
    assert!(
        matches!(cap.authorize_final_disclosure(None, scope()?,digest,&Clock(time(90)?)),Err(error) if error.reason==ConsentErrorReason::PolicyContextMismatch)
    );
    Ok(())
}

#[test]
fn reader_over_asking_is_exposed_for_user_notice() -> Result<(), TestError> {
    let prepared = prepare_reader_receipt_consent(
        &OverAskingReader,
        &(),
        vec![ConsentAction {
            kind: ConsentActionKind::Disclose,
            scope: scope()?,
            derivation_id: None,
            derivation_inputs: vec![],
        }],
        crate::UnregisteredAttributePolicy::WarnAndAllowAll,
        time(20)?,
    )?;
    assert_eq!(
        prepared.unregistered_attributes(),
        &[AttributeName::new("portrait".into())?]
    );
    assert!(prepared_or_empty()?.unregistered_attributes().is_empty());
    Ok(())
}

fn prepared_or_empty() -> Result<PreparedReceiptConsent, TestError> {
    prepared()
}

#[test]
fn plain_and_receipt_capture_of_one_request_share_a_single_claim() -> Result<(), TestError> {
    let mut store = Store::default();
    let plain = prepared()?;
    let plain_capture = capture(&plain);
    crate::capture_prepared_consent(plain.prepared, plain_capture, &Clock(time(20)?), &mut store)?;

    let p = prepared()?;
    let c = capture(&p);
    let digest = *p.context_digest();
    let reader = p.reader().cloned();
    let result =
        capture_receipt_consent(p, c, digest, reader.as_ref(), &Clock(time(20)?), &mut store);

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::CaptureAlreadyUsed
    ));
    assert!(store.receipts.is_empty());
    Ok(())
}

#[test]
fn consent_claim_carries_the_capture_deadline() -> Result<(), TestError> {
    let p = prepared()?;
    let claim = p.prepared.consent_claim();

    assert_eq!(claim.namespace, &rp()?);
    assert_eq!(claim.request_nonce, &p.request().request_nonce);
    assert_eq!(claim.retain_until, p.prepared.authorization_valid_until());
    Ok(())
}
