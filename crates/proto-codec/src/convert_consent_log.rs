// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use std::collections::BTreeSet;

use super::{
    known_enum, unix_timestamp_from_proto, unix_timestamp_to_proto, ConvertError,
    ConvertErrorReason, ConvertResult,
};

const MAX_PREDICATE_BYTES: usize = 4_096;
const MAX_PREDICATE_SET_VALUES: usize = 32;

/// Convert a wallet consent scope into protobuf.
#[must_use]
pub fn consent_scope_to_proto(scope: &wallet::ConsentScope) -> pb::ConsentScope {
    let mut result = pb::ConsentScope::default();
    result.attributes = scope
        .attributes
        .iter()
        .map(|attribute| attribute.as_str().to_owned())
        .collect();
    result
}

/// Convert a generated protobuf consent scope into wallet state.
pub fn consent_scope_from_proto(scope: &pb::ConsentScope) -> ConvertResult<wallet::ConsentScope> {
    let mut attributes = Vec::with_capacity(scope.attributes.len());
    for attribute in &scope.attributes {
        attributes.push(wallet::AttributeName::new(attribute.clone())?);
    }

    Ok(wallet::ConsentScope { attributes })
}

/// Convert a wallet consent action kind into protobuf.
#[must_use]
pub fn consent_action_kind_to_proto(kind: wallet::ConsentActionKind) -> pb::ConsentActionKind {
    match kind {
        wallet::ConsentActionKind::Disclose => pb::ConsentActionKind::CONSENT_ACTION_KIND_DISCLOSE,
        wallet::ConsentActionKind::Derive => pb::ConsentActionKind::CONSENT_ACTION_KIND_DERIVE,
        wallet::ConsentActionKind::QualifiedSignature => {
            pb::ConsentActionKind::CONSENT_ACTION_KIND_QUALIFIED_SIGNATURE
        }
        wallet::ConsentActionKind::QualifiedSeal => {
            pb::ConsentActionKind::CONSENT_ACTION_KIND_QUALIFIED_SEAL
        }
    }
}

/// Convert a generated protobuf consent action kind into wallet type.
pub fn consent_action_kind_from_proto(
    kind: pb::ConsentActionKind,
) -> ConvertResult<wallet::ConsentActionKind> {
    match kind {
        pb::ConsentActionKind::CONSENT_ACTION_KIND_DISCLOSE => {
            Ok(wallet::ConsentActionKind::Disclose)
        }
        pb::ConsentActionKind::CONSENT_ACTION_KIND_DERIVE => Ok(wallet::ConsentActionKind::Derive),
        pb::ConsentActionKind::CONSENT_ACTION_KIND_QUALIFIED_SIGNATURE => {
            Ok(wallet::ConsentActionKind::QualifiedSignature)
        }
        pb::ConsentActionKind::CONSENT_ACTION_KIND_QUALIFIED_SEAL => {
            Ok(wallet::ConsentActionKind::QualifiedSeal)
        }
        pb::ConsentActionKind::CONSENT_ACTION_KIND_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

fn derivation_mode_to_proto(mode: wallet::ConsentDerivationMode) -> pb::ConsentDerivationMode {
    match mode {
        wallet::ConsentDerivationMode::Hidden => {
            pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_HIDDEN
        }
        wallet::ConsentDerivationMode::Reveal => {
            pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_REVEAL
        }
        wallet::ConsentDerivationMode::Eq => pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_EQ,
        wallet::ConsentDerivationMode::Gte => {
            pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_GTE
        }
        wallet::ConsentDerivationMode::Lte => {
            pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_LTE
        }
        wallet::ConsentDerivationMode::Range => {
            pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_RANGE
        }
        wallet::ConsentDerivationMode::MemberOfSet => {
            pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_MEMBER_OF_SET
        }
    }
}

fn derivation_mode_from_proto(
    mode: pb::ConsentDerivationMode,
) -> ConvertResult<wallet::ConsentDerivationMode> {
    match mode {
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_HIDDEN => {
            Ok(wallet::ConsentDerivationMode::Hidden)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_REVEAL => {
            Ok(wallet::ConsentDerivationMode::Reveal)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_EQ => {
            Ok(wallet::ConsentDerivationMode::Eq)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_GTE => {
            Ok(wallet::ConsentDerivationMode::Gte)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_LTE => {
            Ok(wallet::ConsentDerivationMode::Lte)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_RANGE => {
            Ok(wallet::ConsentDerivationMode::Range)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_MEMBER_OF_SET => {
            Ok(wallet::ConsentDerivationMode::MemberOfSet)
        }
        pb::ConsentDerivationMode::CONSENT_DERIVATION_MODE_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

fn derivation_input_to_proto(input: &wallet::ConsentDerivationInput) -> pb::ConsentDerivationInput {
    let mut result = pb::ConsentDerivationInput::default();
    result.attribute = input.attribute.as_str().to_owned();
    result.mode = EnumValue::from(derivation_mode_to_proto(input.mode));
    result.operand_kind = EnumValue::from(match &input.operand {
        wallet::ConsentPredicateOperand::None => {
            pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_NONE
        }
        wallet::ConsentPredicateOperand::Value(value) => {
            result.value = value.clone();
            pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_VALUE
        }
        wallet::ConsentPredicateOperand::Threshold(value) => {
            result.threshold = *value;
            pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_THRESHOLD
        }
        wallet::ConsentPredicateOperand::Range { min, max } => {
            result.range_min = *min;
            result.range_max = *max;
            pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_RANGE
        }
        wallet::ConsentPredicateOperand::Set(values) => {
            result.set_values = values.clone();
            pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_SET
        }
    });
    result
}

fn derivation_input_from_proto(
    input: &pb::ConsentDerivationInput,
) -> ConvertResult<wallet::ConsentDerivationInput> {
    let mode = derivation_mode_from_proto(known_enum(input.mode)?)?;
    let kind = known_enum(input.operand_kind)?;
    let no_value = input.value.is_empty();
    let no_threshold = input.threshold == 0;
    let no_range = input.range_min == 0 && input.range_max == 0;
    let no_set = input.set_values.is_empty();
    let operand = match kind {
        pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_NONE
            if no_value && no_threshold && no_range && no_set =>
        {
            wallet::ConsentPredicateOperand::None
        }
        pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_VALUE
            if !no_value
                && input.value.len() <= MAX_PREDICATE_BYTES
                && no_threshold
                && no_range
                && no_set =>
        {
            wallet::ConsentPredicateOperand::Value(input.value.clone())
        }
        pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_THRESHOLD
            if no_value && no_range && no_set =>
        {
            wallet::ConsentPredicateOperand::Threshold(input.threshold)
        }
        pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_RANGE
            if no_value && no_threshold && no_set && input.range_min <= input.range_max =>
        {
            wallet::ConsentPredicateOperand::Range {
                min: input.range_min,
                max: input.range_max,
            }
        }
        pb::ConsentPredicateOperandKind::CONSENT_PREDICATE_OPERAND_KIND_SET
            if no_value
                && no_threshold
                && no_range
                && !no_set
                && input.set_values.len() <= MAX_PREDICATE_SET_VALUES
                && input
                    .set_values
                    .iter()
                    .all(|value| !value.is_empty() && value.len() <= MAX_PREDICATE_BYTES) =>
        {
            wallet::ConsentPredicateOperand::Set(input.set_values.clone())
        }
        _ => return Err(ConvertError::new(ConvertErrorReason::InvalidConsentAction)),
    };
    let matching = matches!(
        (mode, &operand),
        (
            wallet::ConsentDerivationMode::Hidden | wallet::ConsentDerivationMode::Reveal,
            wallet::ConsentPredicateOperand::None
        ) | (
            wallet::ConsentDerivationMode::Eq,
            wallet::ConsentPredicateOperand::Value(_)
        ) | (
            wallet::ConsentDerivationMode::Gte | wallet::ConsentDerivationMode::Lte,
            wallet::ConsentPredicateOperand::Threshold(_)
        ) | (
            wallet::ConsentDerivationMode::Range,
            wallet::ConsentPredicateOperand::Range { .. }
        ) | (
            wallet::ConsentDerivationMode::MemberOfSet,
            wallet::ConsentPredicateOperand::Set(_)
        )
    );
    if !matching {
        return Err(ConvertError::new(ConvertErrorReason::InvalidConsentAction));
    }
    Ok(wallet::ConsentDerivationInput {
        attribute: wallet::AttributeName::new(input.attribute.clone())?,
        mode,
        operand,
    })
}

/// Convert a wallet consent action into protobuf.
#[must_use]
pub fn consent_action_to_proto(action: &wallet::ConsentAction) -> pb::ConsentAction {
    let mut result = pb::ConsentAction::default();
    result.kind = EnumValue::from(consent_action_kind_to_proto(action.kind));
    result.scope = MessageField::some(consent_scope_to_proto(&action.scope));
    result.derivation_id = action
        .derivation_id
        .as_ref()
        .map_or_else(String::new, |id| id.as_str().to_owned());
    result.derivation_inputs = action
        .derivation_inputs
        .iter()
        .map(derivation_input_to_proto)
        .collect();
    result
}

/// Convert a generated protobuf consent action into wallet type.
pub fn consent_action_from_proto(
    action: &pb::ConsentAction,
) -> ConvertResult<wallet::ConsentAction> {
    let scope = action
        .scope
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(consent_scope_from_proto)?;
    let derivation_id = if action.derivation_id.is_empty() {
        None
    } else {
        Some(wallet::NonEmptyIdentifier::new(
            action.derivation_id.clone(),
        )?)
    };

    let kind = consent_action_kind_from_proto(known_enum(action.kind)?)?;
    let derivation_inputs = action
        .derivation_inputs
        .iter()
        .map(derivation_input_from_proto)
        .collect::<ConvertResult<Vec<_>>>()?;
    if (kind == wallet::ConsentActionKind::Derive) != !derivation_inputs.is_empty()
        || (kind == wallet::ConsentActionKind::Derive) != derivation_id.is_some()
    {
        return Err(ConvertError::new(ConvertErrorReason::InvalidConsentAction));
    }
    if kind == wallet::ConsentActionKind::Derive {
        let scope_attributes = scope.attributes.iter().collect::<BTreeSet<_>>();
        let input_attributes = derivation_inputs
            .iter()
            .map(|input| &input.attribute)
            .collect::<BTreeSet<_>>();
        if scope_attributes.len() != scope.attributes.len()
            || input_attributes.len() != derivation_inputs.len()
            || scope_attributes != input_attributes
        {
            return Err(ConvertError::new(ConvertErrorReason::InvalidConsentAction));
        }
    }
    Ok(wallet::ConsentAction {
        kind,
        scope,
        derivation_id,
        derivation_inputs,
    })
}

/// Convert a wallet disclosure policy decision into protobuf.
#[must_use]
pub fn disclosure_policy_decision_to_proto(
    decision: wallet::DisclosurePolicyDecision,
) -> pb::DisclosurePolicyDecision {
    match decision {
        wallet::DisclosurePolicyDecision::Allowed => {
            pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_ALLOWED
        }
        wallet::DisclosurePolicyDecision::Denied => {
            pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_DENIED
        }
        wallet::DisclosurePolicyDecision::AllowedWithUnregisteredRequest => {
            pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_ALLOWED_WITH_UNREGISTERED_REQUEST
        }
    }
}

/// Convert a generated protobuf disclosure policy decision into wallet type.
pub fn disclosure_policy_decision_from_proto(
    decision: pb::DisclosurePolicyDecision,
) -> ConvertResult<wallet::DisclosurePolicyDecision> {
    match decision {
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_ALLOWED => {
            Ok(wallet::DisclosurePolicyDecision::Allowed)
        }
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_DENIED => {
            Ok(wallet::DisclosurePolicyDecision::Denied)
        }
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_ALLOWED_WITH_UNREGISTERED_REQUEST => {
            Ok(wallet::DisclosurePolicyDecision::AllowedWithUnregisteredRequest)
        }
        pb::DisclosurePolicyDecision::DISCLOSURE_POLICY_DECISION_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet consent request into protobuf.
#[must_use]
pub fn consent_request_to_proto(request: &wallet::ConsentRequest) -> pb::ConsentRequest {
    let mut result = pb::ConsentRequest::default();
    result.relying_party_id = request.relying_party_id.as_str().to_owned();
    result.requested_scope = MessageField::some(consent_scope_to_proto(&request.requested_scope));
    result.policy_decision =
        EnumValue::from(disclosure_policy_decision_to_proto(request.policy_decision));
    result.actions = request
        .actions
        .iter()
        .map(consent_action_to_proto)
        .collect();
    result.created_at = MessageField::some(unix_timestamp_to_proto(request.created_at));
    result.request_nonce = request.request_nonce.as_str().to_owned();
    result.request_digest = request.request_digest.to_vec();
    result
}

/// Convert a generated protobuf consent request into wallet type.
pub fn consent_request_from_proto(
    request: &pb::ConsentRequest,
) -> ConvertResult<wallet::ConsentRequest> {
    let requested_scope = request
        .requested_scope
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(consent_scope_from_proto)?;
    let created_at = request
        .created_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    let mut actions = Vec::with_capacity(request.actions.len());
    for action in &request.actions {
        actions.push(consent_action_from_proto(action)?);
    }
    let request_digest =
        <[u8; wallet::CONSENT_REQUEST_DIGEST_BYTES]>::try_from(request.request_digest.as_slice())
            .map_err(|_| ConvertError::new(ConvertErrorReason::IntegerOutOfRange))?;
    if request_digest.iter().all(|byte| *byte == 0) {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIdentifier));
    }

    Ok(wallet::ConsentRequest {
        relying_party_id: wallet::RelyingPartyId::new(request.relying_party_id.clone())?,
        requested_scope,
        policy_decision: disclosure_policy_decision_from_proto(known_enum(
            request.policy_decision,
        )?)?,
        actions,
        request_nonce: wallet::NonEmptyIdentifier::new(request.request_nonce.clone())?,
        request_digest,
        created_at,
    })
}

/// Convert a wallet verifier entitlement into protobuf.
#[must_use]
pub fn verifier_entitlement_to_proto(
    entitlement: &wallet::VerifierEntitlement,
) -> pb::VerifierEntitlement {
    let mut result = pb::VerifierEntitlement::default();
    result.relying_party_id = entitlement.relying_party_id.as_str().to_owned();
    result.authorized_scope =
        MessageField::some(consent_scope_to_proto(&entitlement.authorized_scope));
    result.valid_until = MessageField::some(unix_timestamp_to_proto(entitlement.valid_until));
    result
}

/// Convert a generated protobuf verifier entitlement into wallet state.
pub fn verifier_entitlement_from_proto(
    entitlement: &pb::VerifierEntitlement,
) -> ConvertResult<wallet::VerifierEntitlement> {
    let authorized_scope = entitlement
        .authorized_scope
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(consent_scope_from_proto)?;
    let valid_until = entitlement
        .valid_until
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;

    Ok(wallet::VerifierEntitlement {
        relying_party_id: wallet::RelyingPartyId::new(entitlement.relying_party_id.clone())?,
        authorized_scope,
        valid_until,
    })
}
