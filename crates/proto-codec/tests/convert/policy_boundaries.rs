// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire DTOs preserve policy evidence and cannot create attestation authority.

use std::cell::Cell;

use buffa::{EnumValue, Message, MessageField};
use reallyme_wallet_attestation as attestation;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::convert::{
    consent_request_from_proto, consent_request_to_proto, wallet_unit_attestation_to_proto,
    ConvertErrorReason,
};
use reallyme_wallet_proto_codec::decode::{decode_consent_request, decode_wallet_unit_attestation};
use reallyme_wallet_proto_codec::encode::encode_consent_request;
use reallyme_wallet_proto_codec::{wallet_proto_from_json, wallet_proto_to_json, ProtoErrorReason};
use reallyme_wallet_types as wallet;

use super::{consent_request, timestamp_at, wallet_unit_attestation, ConvertFixtureError};

#[test]
fn all_wire_policy_results_preserve_binary_request_bindings() -> Result<(), ConvertFixtureError> {
    for decision in [
        wallet::DisclosurePolicyDecision::Allowed,
        wallet::DisclosurePolicyDecision::Denied,
        wallet::DisclosurePolicyDecision::AllowedWithUnregisteredRequest,
    ] {
        let mut request = consent_request()?;
        request.policy_decision = decision;
        let bytes = encode_consent_request(&request)?;
        assert!(decode_consent_request(&bytes)? == request);
    }
    Ok(())
}

#[test]
fn public_operation_protojson_preserves_all_policy_result_values() -> Result<(), ConvertFixtureError>
{
    for decision in [
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_ALLOWED,
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_DENIED,
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_ALLOWED_WITH_UNREGISTERED_REQUEST,
    ] {
        // ProtoJSON is intentionally sealed to the operation envelopes. The
        // test uses that supported surface rather than inventing DTO JSON.
        // This checks serialized evidence; the runtime's unverified-entitlement
        // operation remains unsupported and gains no authority from decoding.
        let result = pb::WalletOperationResult {
            result: Some(
                pb::wallet_operation_result::Result::EvaluateVerifierEntitlement(Box::new(
                    pb::EvaluateVerifierEntitlementResponse {
                        decision: decision.into(),
                        ..pb::EvaluateVerifierEntitlementResponse::default()
                    },
                )),
            ),
            ..pb::WalletOperationResult::default()
        };
        let json = wallet_proto_to_json(&result)?;
        let decoded: pb::WalletOperationResult = wallet_proto_from_json(&json)?;
        assert!(matches!(decoded.result,
            Some(pb::wallet_operation_result::Result::EvaluateVerifierEntitlement(response))
                if response.decision == EnumValue::from(decision)));
    }
    Ok(())
}

#[test]
fn unspecified_and_unknown_policy_results_fail_before_domain_conversion(
) -> Result<(), ConvertFixtureError> {
    for value in [0_i32, -1, 4, i32::MAX] {
        let mut wire = consent_request_to_proto(&consent_request()?);
        wire.policy_decision = EnumValue::from(value);
        assert!(
            matches!(consent_request_from_proto(&wire), Err(error) if error.reason == ConvertErrorReason::InvalidEnumValue)
        );
        assert!(
            matches!(decode_consent_request(&wire.encode_to_vec()), Err(error) if error.reason == ProtoErrorReason::InvalidDto)
        );
    }
    Ok(())
}

#[test]
fn a_narrowed_registered_scope_retains_its_unregistered_request_warning(
) -> Result<(), ConvertFixtureError> {
    let mut request = consent_request()?;
    request.policy_decision = wallet::DisclosurePolicyDecision::AllowedWithUnregisteredRequest;
    request.actions = vec![wallet::ConsentAction {
        kind: wallet::ConsentActionKind::Disclose,
        scope: request.requested_scope.clone(),
        derivation_id: None,
        derivation_inputs: Vec::new(),
    }];
    let bytes = encode_consent_request(&request)?;
    let restored = decode_consent_request(&bytes)?;
    assert!(restored == request);
    assert_eq!(
        restored.policy_decision,
        wallet::DisclosurePolicyDecision::AllowedWithUnregisteredRequest
    );
    assert_eq!(
        restored.requested_scope.attributes,
        vec![wallet::AttributeName::new("age_over_18".to_owned())?]
    );
    assert_eq!(
        restored.actions[0].scope.attributes,
        restored.requested_scope.attributes
    );
    Ok(())
}

struct CountingAttestationVerifier(Cell<u32>);

impl attestation::WalletUnitAttestationVerifier for CountingAttestationVerifier {
    fn verify_wallet_unit_attestation(
        &self,
        _: &attestation::UnverifiedWalletUnitAttestation,
        _: wallet::UnixTimestamp,
    ) -> attestation::AttestationResult<attestation::VerifiedWalletKeyThumbprint> {
        let calls = self.0.get().checked_add(1).ok_or_else(|| {
            attestation::AttestationError::new(
                attestation::AttestationErrorReason::InvalidAttestationEvidence,
            )
        })?;
        self.0.set(calls);
        attestation::VerifiedWalletKeyThumbprint::new([1; 32])
    }
}

#[test]
fn decoded_attestation_lifetimes_cannot_bypass_wallet_verification(
) -> Result<(), ConvertFixtureError> {
    let verified = wallet_unit_attestation()?;
    for (lifetime, accepted) in [(86_399_i64, true), (86_400, false), (86_401, false)] {
        let mut wire = wallet_unit_attestation_to_proto(&verified);
        let expiry = 10_i64.checked_add(lifetime).ok_or_else(|| {
            attestation::AttestationError::new(
                attestation::AttestationErrorReason::InvalidValidityWindow,
            )
        })?;
        wire.valid_until = MessageField::some(pb::UnixTimestamp {
            seconds: expiry,
            ..pb::UnixTimestamp::default()
        });
        // Bounded decoding yields unverified evidence. Well-formed timestamp
        // fields cannot promote a persisted record into authorization.
        let decoded = decode_wallet_unit_attestation(&wire.encode_to_vec())?;
        assert_eq!(decoded.valid_until(), timestamp_at(expiry)?);
        let verifier = CountingAttestationVerifier(Cell::new(0));
        let result = attestation::verify_wallet_unit_attestation_for_key(
            decoded,
            &verifier,
            timestamp_at(15)?,
            &wallet::KeyHandleId::new("key-1".to_owned())?,
            &[1; 32],
        );
        if accepted {
            assert!(result.is_ok());
            assert_eq!(verifier.0.get(), 1);
        } else {
            assert!(
                matches!(result, Err(error) if error.reason == attestation::AttestationErrorReason::InvalidValidityWindow)
            );
            assert_eq!(verifier.0.get(), 0);
        }
    }
    Ok(())
}
