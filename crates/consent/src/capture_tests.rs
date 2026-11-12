// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::{
    AttributeName, ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision,
    ConsentDerivationInput, ConsentDerivationMode, ConsentPredicateOperand, ConsentScope,
    DisclosurePolicyDecision, NonEmptyIdentifier, UnixTimestamp, VerifierEntitlement,
    WalletTypesError,
};

use super::{
    capture_prepared_consent as capture_prepared_consent_with_store,
    prepare_consent_request_from_entitlement, CapturedConsent, ConsentCaptureStore,
    PreparedConsentRequest, TrustedConsentClock,
};
use crate::{
    ConsentCaptureStoreError, ConsentCaptureStoreErrorReason, ConsentError, ConsentErrorReason,
    ConsentResult,
};
use std::collections::BTreeSet;

#[path = "capture_claim_namespace_tests.rs"]
mod claim_namespace_tests;

#[path = "capture_policy_plan_tests.rs"]
mod policy_plan_tests;

fn attr(value: &str) -> Result<AttributeName, WalletTypesError> {
    AttributeName::new(value.to_owned())
}

fn id(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(value: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(value)
}

struct FixedClock(UnixTimestamp);

impl TrustedConsentClock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        self.0
    }
}

#[derive(Default)]
struct MemoryCaptureStore {
    claimed: BTreeSet<(String, String)>,
    unavailable: bool,
}

impl ConsentCaptureStore for MemoryCaptureStore {
    fn claim_capture(
        &mut self,
        claim: &crate::ConsentClaim<'_>,
        receipt: Option<&reallyme_wallet_types::ConsentReceipt>,
    ) -> Result<(), ConsentCaptureStoreError> {
        // This store keeps no receipts, so it must refuse one, not drop it.
        if receipt.is_some() {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::ReceiptUnsupported,
            ));
        }
        if self.unavailable {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::Unavailable,
            ));
        }
        if !self.claimed.insert((
            claim.namespace.as_str().to_owned(),
            claim.request_nonce.as_str().to_owned(),
        )) {
            return Err(ConsentCaptureStoreError::new(
                ConsentCaptureStoreErrorReason::AlreadyClaimed,
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
    capture_prepared_consent_with_store(
        prepared,
        capture,
        clock,
        &mut MemoryCaptureStore::default(),
    )
}

fn prepare_consent_request(
    entitlement: &VerifierEntitlement,
    requested_scope: ConsentScope,
    actions: Vec<ConsentAction>,
    now: UnixTimestamp,
) -> ConsentResult<super::PreparedConsentRequest> {
    prepare_consent_request_from_entitlement(
        entitlement,
        requested_scope,
        actions,
        NonEmptyIdentifier::new("request-nonce-1".to_owned())
            .map_err(|_| ConsentError::new(ConsentErrorReason::RequestBindingMismatch))?,
        [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        crate::UnregisteredAttributePolicy::WarnAndAllowAll,
        now,
    )
}

fn entitlement() -> Result<VerifierEntitlement, WalletTypesError> {
    Ok(VerifierEntitlement {
        relying_party_id: id("rp-1")?,
        authorized_scope: ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        valid_until: timestamp(20)?,
    })
}

fn disclose_action() -> Result<ConsentAction, WalletTypesError> {
    Ok(ConsentAction {
        kind: ConsentActionKind::Disclose,
        scope: ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        derivation_id: None,
        derivation_inputs: Vec::new(),
    })
}

fn derive_action(threshold: u64) -> Result<ConsentAction, WalletTypesError> {
    Ok(ConsentAction {
        kind: ConsentActionKind::Derive,
        scope: ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        derivation_id: Some(id("age-proof")?),
        derivation_inputs: vec![ConsentDerivationInput {
            attribute: attr("age_over_18")?,
            mode: ConsentDerivationMode::Gte,
            operand: ConsentPredicateOperand::Threshold(threshold),
        }],
    })
}

#[test]
fn capture_rejects_changed_predicate_operand() -> Result<(), TestError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![derive_action(18)?],
        timestamp(10)?,
    )?;
    let mut capture = capture_for_request(&request, timestamp(11)?);
    capture.selected_action = derive_action(21)?;
    assert!(matches!(
        capture_prepared_consent(request, capture, &FixedClock(timestamp(11)?)),
        Err(error) if error.reason == ConsentErrorReason::RequestBindingMismatch
    ));
    Ok(())
}

fn capture_for_request(
    request: &super::PreparedConsentRequest,
    captured_at: UnixTimestamp,
) -> ConsentCapture {
    ConsentCapture {
        relying_party_id: request.request().relying_party_id.clone(),
        requested_scope: request.request().requested_scope.clone(),
        selected_action: request.request().actions[0].clone(),
        request_nonce: request.request().request_nonce.clone(),
        request_digest: request.request().request_digest,
        policy_decision: DisclosurePolicyDecision::Allowed,
        user_decision: ConsentDecision::Approved,
        captured_at,
    }
}

#[test]
fn capture_rejects_expiry_after_preparation() -> Result<(), TestError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(19)?,
    )?;
    let capture = capture_for_request(&request, timestamp(21)?);

    assert!(matches!(
        capture_prepared_consent(request, capture, &FixedClock(timestamp(21)?)),
        Err(error) if error.reason == ConsentErrorReason::EntitlementExpired
    ));
    Ok(())
}

#[test]
fn capture_rejects_backdated_or_regressed_time() -> Result<(), TestError> {
    for (prepared_at, claimed_at, clock_at) in [(10, 11, 12), (10, 9, 9)] {
        let request = prepare_consent_request(
            &entitlement()?,
            ConsentScope {
                attributes: vec![attr("age_over_18")?],
            },
            vec![disclose_action()?],
            timestamp(prepared_at)?,
        )?;
        let capture = capture_for_request(&request, timestamp(claimed_at)?);
        assert!(matches!(
            capture_prepared_consent(request, capture, &FixedClock(timestamp(clock_at)?)),
            Err(error) if error.reason == ConsentErrorReason::RequestBindingMismatch
        ));
    }
    Ok(())
}

#[test]
fn capture_accepts_trusted_time_within_entitlement() -> Result<(), TestError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    let capture = capture_for_request(&request, timestamp(11)?);
    let captured = capture_prepared_consent(request, capture, &FixedClock(timestamp(11)?))?;
    assert_eq!(captured.record().captured_at, timestamp(11)?);
    assert_eq!(format!("{captured:?}"), "CapturedConsent(<redacted>)");
    Ok(())
}

#[test]
fn final_disclosure_rejects_unselected_and_duplicate_attributes() -> Result<(), TestError> {
    for attributes in [
        vec![attr("unapproved")?],
        vec![attr("age_over_18")?, attr("age_over_18")?],
    ] {
        let request = prepare_consent_request(
            &entitlement()?,
            ConsentScope {
                attributes: vec![attr("age_over_18")?],
            },
            vec![disclose_action()?],
            timestamp(10)?,
        )?;
        let capture = capture_for_request(&request, timestamp(11)?);
        let captured = capture_prepared_consent(request, capture, &FixedClock(timestamp(11)?))?;
        assert!(matches!(
            captured.authorize_scope(ConsentScope { attributes }),
            Err(error) if error.reason == ConsentErrorReason::FinalDisclosureOutOfScope
        ));
    }
    Ok(())
}

#[test]
fn final_disclosure_allows_only_revealed_derivation_inputs() -> Result<(), TestError> {
    for mode in [ConsentDerivationMode::Gte, ConsentDerivationMode::Reveal] {
        let mut action = derive_action(18)?;
        action.derivation_inputs[0].mode = mode;
        action.derivation_inputs[0].operand = if mode == ConsentDerivationMode::Reveal {
            ConsentPredicateOperand::None
        } else {
            ConsentPredicateOperand::Threshold(18)
        };
        let request = prepare_consent_request(
            &entitlement()?,
            ConsentScope {
                attributes: vec![attr("age_over_18")?],
            },
            vec![action],
            timestamp(10)?,
        )?;
        let capture = capture_for_request(&request, timestamp(11)?);
        let captured = capture_prepared_consent(request, capture, &FixedClock(timestamp(11)?))?;
        let result = captured.authorize_scope(ConsentScope {
            attributes: vec![attr("age_over_18")?],
        });
        if mode == ConsentDerivationMode::Reveal {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(error) if error.reason == ConsentErrorReason::FinalDisclosureOutOfScope
            ));
        }
    }
    Ok(())
}

#[test]
fn capture_claim_is_single_use_across_separate_preparations() -> Result<(), TestError> {
    let scope = ConsentScope {
        attributes: vec![attr("age_over_18")?],
    };
    let first = prepare_consent_request(
        &entitlement()?,
        scope.clone(),
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    let second = prepare_consent_request(
        &entitlement()?,
        scope.clone(),
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    let changed_digest = prepare_consent_request_from_entitlement(
        &entitlement()?,
        scope,
        vec![disclose_action()?],
        id("request-nonce-1")?,
        [8; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        crate::UnregisteredAttributePolicy::WarnAndAllowAll,
        timestamp(10)?,
    )?;
    let first_capture = capture_for_request(&first, timestamp(11)?);
    let second_capture = capture_for_request(&second, timestamp(11)?);
    let changed_digest_capture = capture_for_request(&changed_digest, timestamp(11)?);
    let mut store = MemoryCaptureStore::default();

    capture_prepared_consent_with_store(
        first,
        first_capture,
        &FixedClock(timestamp(11)?),
        &mut store,
    )?;
    assert!(matches!(
        capture_prepared_consent_with_store(
            second,
            second_capture,
            &FixedClock(timestamp(11)?),
            &mut store,
        ),
        Err(error) if error.reason == ConsentErrorReason::CaptureAlreadyUsed
    ));
    assert!(matches!(
        capture_prepared_consent_with_store(
            changed_digest,
            changed_digest_capture,
            &FixedClock(timestamp(11)?),
            &mut store,
        ),
        Err(error) if error.reason == ConsentErrorReason::CaptureAlreadyUsed
    ));
    assert_eq!(store.claimed.len(), 1);
    Ok(())
}

#[test]
fn capture_fails_closed_when_claim_store_is_unavailable() -> Result<(), TestError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    let capture = capture_for_request(&request, timestamp(11)?);
    let mut store = MemoryCaptureStore {
        unavailable: true,
        ..MemoryCaptureStore::default()
    };

    assert!(matches!(
        capture_prepared_consent_with_store(
            request,
            capture,
            &FixedClock(timestamp(11)?),
            &mut store,
        ),
        Err(error) if error.reason == ConsentErrorReason::CaptureStoreUnavailable
    ));
    assert!(store.claimed.is_empty());
    Ok(())
}

#[test]
fn prepares_disclosure_consent_request() -> Result<(), WalletTypesError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(10)?,
    );

    assert!(matches!(request, Ok(request) if request.request().actions.len() == 1));
    Ok(())
}

#[test]
fn prepares_qualified_signature_consent_request() -> Result<(), WalletTypesError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![ConsentAction {
            kind: ConsentActionKind::QualifiedSignature,
            scope: ConsentScope {
                attributes: vec![attr("age_over_18")?],
            },
            derivation_id: None,
            derivation_inputs: Vec::new(),
        }],
        timestamp(10)?,
    );

    assert!(matches!(
        request,
        Ok(request)
            if request.request().actions.len() == 1
                && request.request().actions[0].kind == ConsentActionKind::QualifiedSignature
    ));
    Ok(())
}

#[test]
fn rejects_derivation_without_identifier() -> Result<(), WalletTypesError> {
    let result = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![ConsentAction {
            kind: ConsentActionKind::Derive,
            scope: ConsentScope {
                attributes: vec![attr("age_over_18")?],
            },
            derivation_id: None,
            derivation_inputs: Vec::new(),
        }],
        timestamp(10)?,
    );

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::DerivationIdentifierMissing
    ));
    Ok(())
}

#[test]
fn rejects_capture_for_different_relying_party() -> Result<(), TestError> {
    let request = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    let capture = ConsentCapture {
        relying_party_id: id("rp-2")?,
        requested_scope: request.request().requested_scope.clone(),
        selected_action: request.request().actions[0].clone(),
        request_nonce: request.request().request_nonce.clone(),
        request_digest: request.request().request_digest,
        policy_decision: DisclosurePolicyDecision::Allowed,
        user_decision: ConsentDecision::Approved,
        captured_at: timestamp(11)?,
    };

    let result = capture_prepared_consent(request, capture, &FixedClock(timestamp(11)?));

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::RelyingPartyMismatch
    ));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("consent")]
    Consent(#[from] ConsentError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}

#[test]
fn over_asking_is_reported_for_user_notice_instead_of_refused() -> Result<(), TestError> {
    let requested = ConsentScope {
        attributes: vec![
            attr("age_over_18")?,
            attr("family_name")?,
            attr("given_name")?,
        ],
    };
    let action = ConsentAction {
        kind: ConsentActionKind::Disclose,
        scope: requested.clone(),
        derivation_id: None,
        derivation_inputs: Vec::new(),
    };
    let prepared =
        prepare_consent_request(&entitlement()?, requested, vec![action], timestamp(10)?)?;

    assert_eq!(
        prepared.unregistered_attributes(),
        &[attr("family_name")?, attr("given_name")?]
    );
    assert_eq!(
        prepared.request().policy_decision,
        DisclosurePolicyDecision::AllowedWithUnregisteredRequest
    );

    let registered_only = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    assert!(registered_only.unregistered_attributes().is_empty());
    assert_eq!(
        registered_only.request().policy_decision,
        DisclosurePolicyDecision::Allowed
    );
    Ok(())
}

#[test]
fn a_capture_that_drops_the_unregistered_warning_is_refused() -> Result<(), TestError> {
    let request = over_asking_request(crate::UnregisteredAttributePolicy::WarnAndAllowAll, None)??;
    let mut capture = capture_for_request(&request, timestamp(11)?);
    capture.policy_decision = DisclosurePolicyDecision::Allowed;

    let result = capture_prepared_consent(request, capture, &FixedClock(timestamp(11)?));

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::PolicyDenied
    ));
    Ok(())
}

fn over_asking_request(
    policy: crate::UnregisteredAttributePolicy,
    derivation_id: Option<NonEmptyIdentifier>,
) -> Result<ConsentResult<PreparedConsentRequest>, TestError> {
    let requested = ConsentScope {
        attributes: vec![attr("age_over_18")?, attr("family_name")?],
    };
    let action = ConsentAction {
        kind: ConsentActionKind::Disclose,
        scope: requested.clone(),
        derivation_id,
        derivation_inputs: Vec::new(),
    };
    Ok(prepare_consent_request_from_entitlement(
        &entitlement()?,
        requested,
        vec![action],
        id("request-nonce-1")?,
        [7; reallyme_wallet_types::CONSENT_REQUEST_DIGEST_BYTES],
        policy,
        timestamp(10)?,
    ))
}

#[test]
fn registered_only_policy_removes_unregistered_attributes_and_still_warns() -> Result<(), TestError>
{
    let prepared = over_asking_request(crate::UnregisteredAttributePolicy::RegisteredOnly, None)??;

    let registered = vec![attr("age_over_18")?];
    assert_eq!(prepared.unregistered_attributes(), &[attr("family_name")?]);
    assert_eq!(prepared.request().requested_scope.attributes, registered);
    assert!(prepared
        .request()
        .actions
        .iter()
        .all(|action| action.scope.attributes == registered));
    Ok(())
}

#[test]
fn registered_only_policy_refuses_to_narrow_a_derived_proof() -> Result<(), TestError> {
    let result = over_asking_request(
        crate::UnregisteredAttributePolicy::RegisteredOnly,
        Some(id("age-derivation-1")?),
    )?;

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::AttributeNotAuthorized
    ));
    Ok(())
}

#[test]
fn reject_policy_refuses_any_unregistered_attribute() -> Result<(), TestError> {
    let result = over_asking_request(crate::UnregisteredAttributePolicy::RejectRequest, None)?;

    assert!(matches!(
        result,
        Err(error) if error.reason == ConsentErrorReason::AttributeNotAuthorized
    ));
    Ok(())
}

#[test]
fn consent_claim_uses_the_verified_client_namespace_and_earliest_deadline() -> Result<(), TestError>
{
    let mut prepared = prepare_consent_request(
        &entitlement()?,
        ConsentScope {
            attributes: vec![attr("age_over_18")?],
        },
        vec![disclose_action()?],
        timestamp(10)?,
    )?;
    let namespace = id("client-sha256:verifier")?;
    prepared.claim_scope = Some(namespace.clone());
    prepared.request_expires_at = Some(timestamp(15)?);

    let claim = prepared.consent_claim();

    assert_eq!(claim.namespace, &namespace);
    assert_eq!(claim.relying_party_id, &prepared.request().relying_party_id);
    assert_eq!(claim.retain_until, timestamp(15)?);
    Ok(())
}
