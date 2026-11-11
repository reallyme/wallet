// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded canonical receipt record conversion.

use super::codec::{
    decode, encode, invalid, nonzero, require, text, timestamp, MAX_POLICY_IDENTIFIER_BYTES,
    POLICY_SCHEMA_VERSION,
};
use crate::convert::{
    consent_action_from_proto, consent_action_to_proto, consent_scope_from_proto,
    consent_scope_to_proto, disclosure_policy_decision_from_proto,
    disclosure_policy_decision_to_proto, unix_timestamp_from_proto, unix_timestamp_to_proto,
};
use crate::ProtoResult;
use buffa::MessageField;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

pub(super) fn policy_to_proto(
    v: &wallet::ConsentPolicyContext,
) -> ProtoResult<pb::ConsentPolicyContext> {
    require(v.policies.len() <= wallet::MAX_CONSENT_POLICIES)?;
    let mut p = pb::ConsentPolicyContext::default();
    p.purpose = v.purpose.as_str().to_owned();
    match v.retention {
        wallet::ConsentRetention::NoRetention => {
            p.retention = pb::ConsentRetentionKind::CONSENT_RETENTION_KIND_NO_RETENTION.into()
        }
        wallet::ConsentRetention::Until(time) => {
            p.retention = pb::ConsentRetentionKind::CONSENT_RETENTION_KIND_UNTIL.into();
            p.retention_until = time.as_seconds();
        }
    }
    p.policies = v
        .policies
        .iter()
        .map(|v| {
            let mut c = pb::ConsentPolicyChoice::default();
            c.id = v.id.as_str().to_owned();
            c.version = v.version.as_str().to_owned();
            c.document_digest = v.document_digest.to_vec();
            c.mandatory = v.mandatory;
            c.accepted = v.accepted;
            c
        })
        .collect();
    p.transaction_digest = v.transaction_digest.to_vec();
    Ok(p)
}

pub(super) fn policy_from_proto(
    p: &pb::ConsentPolicyContext,
) -> ProtoResult<wallet::ConsentPolicyContext> {
    require(p.policies.len() <= wallet::MAX_CONSENT_POLICIES)?;
    let retention = match p.retention.as_known().ok_or_else(invalid)? {
        pb::ConsentRetentionKind::CONSENT_RETENTION_KIND_NO_RETENTION if p.retention_until == 0 => {
            wallet::ConsentRetention::NoRetention
        }
        pb::ConsentRetentionKind::CONSENT_RETENTION_KIND_UNTIL => {
            wallet::ConsentRetention::Until(timestamp(p.retention_until)?)
        }
        _ => return Err(invalid()),
    };
    let mut policies = Vec::with_capacity(p.policies.len());
    for c in &p.policies {
        require(!c.mandatory || c.accepted)?;
        policies.push(wallet::ConsentPolicyChoice {
            id: wallet::NonEmptyIdentifier::new(text(&c.id)?).map_err(|_| invalid())?,
            version: wallet::NonEmptyIdentifier::new(text(&c.version)?).map_err(|_| invalid())?,
            document_digest: nonzero(&c.document_digest)?,
            mandatory: c.mandatory,
            accepted: c.accepted,
        });
    }
    require(policies.windows(2).all(|pair| pair[0].id < pair[1].id))?;
    Ok(wallet::ConsentPolicyContext {
        purpose: wallet::NonEmptyIdentifier::new(text(&p.purpose)?).map_err(|_| invalid())?,
        retention,
        policies,
        transaction_digest: nonzero(&p.transaction_digest)?,
    })
}

pub(super) fn reader_to_proto(v: &wallet::ReaderSessionBinding) -> pb::ReaderSessionBinding {
    let mut p = pb::ReaderSessionBinding::default();
    p.reader_id = v.reader_id.as_str().to_owned();
    p.certificate_digest = v.certificate_digest.to_vec();
    p.session_digest = v.session_digest.to_vec();
    p.request_digest = v.request_digest.to_vec();
    p.authenticated_at = v.authenticated_at.as_seconds();
    p.valid_until = v.valid_until.as_seconds();
    p
}

pub(super) fn reader_from_proto(
    p: &pb::ReaderSessionBinding,
) -> ProtoResult<wallet::ReaderSessionBinding> {
    let from = timestamp(p.authenticated_at)?;
    let until = timestamp(p.valid_until)?;
    require(from < until)?;
    Ok(wallet::ReaderSessionBinding {
        reader_id: wallet::RelyingPartyId::new(text(&p.reader_id)?).map_err(|_| invalid())?,
        certificate_digest: nonzero(&p.certificate_digest)?,
        session_digest: nonzero(&p.session_digest)?,
        request_digest: nonzero(&p.request_digest)?,
        authenticated_at: from,
        valid_until: until,
    })
}

pub(super) fn capture_to_proto(v: &wallet::ConsentCapture) -> ProtoResult<pb::ConsentCapture> {
    require(
        v.requested_scope.attributes.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && v.selected_action.scope.attributes.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && v.selected_action.derivation_inputs.len() <= wallet::MAX_HISTORY_ATTRIBUTES,
    )?;
    const MAX_PREDICATE_BYTES: usize = 4_096;
    const MAX_PREDICATE_SET_VALUES: usize = 32;
    const MAX_RECEIPT_PREDICATE_BYTES: usize = 1_048_576;
    let mut total = 0_usize;
    for input in &v.selected_action.derivation_inputs {
        match &input.operand {
            wallet::ConsentPredicateOperand::Value(value) => {
                require(value.len() <= MAX_PREDICATE_BYTES)?;
                total = total.checked_add(value.len()).ok_or_else(invalid)?;
            }
            wallet::ConsentPredicateOperand::Set(values) => {
                require(values.len() <= MAX_PREDICATE_SET_VALUES)?;
                for value in values {
                    require(value.len() <= MAX_PREDICATE_BYTES)?;
                    total = total.checked_add(value.len()).ok_or_else(invalid)?;
                }
            }
            wallet::ConsentPredicateOperand::None
            | wallet::ConsentPredicateOperand::Threshold(_)
            | wallet::ConsentPredicateOperand::Range { .. } => {}
        }
        require(total <= MAX_RECEIPT_PREDICATE_BYTES)?;
    }
    let mut p = pb::ConsentCapture::default();
    p.relying_party_id = v.relying_party_id.as_str().to_owned();
    p.requested_scope = MessageField::some(consent_scope_to_proto(&v.requested_scope));
    p.policy_decision = disclosure_policy_decision_to_proto(v.policy_decision).into();
    p.user_decision = match v.user_decision {
        wallet::ConsentDecision::Approved => pb::ConsentDecision::CONSENT_DECISION_APPROVED.into(),
        wallet::ConsentDecision::Rejected => pb::ConsentDecision::CONSENT_DECISION_REJECTED.into(),
    };
    p.captured_at = MessageField::some(unix_timestamp_to_proto(v.captured_at));
    p.selected_action = MessageField::some(consent_action_to_proto(&v.selected_action));
    p.request_nonce = v.request_nonce.as_str().to_owned();
    p.request_digest = v.request_digest.to_vec();
    Ok(p)
}

pub(super) fn capture_from_proto(p: &pb::ConsentCapture) -> ProtoResult<wallet::ConsentCapture> {
    let raw_scope = p.requested_scope.as_option().ok_or_else(invalid)?;
    let raw_action = p.selected_action.as_option().ok_or_else(invalid)?;
    let action_scope = raw_action.scope.as_option().ok_or_else(invalid)?;
    require(
        raw_scope.attributes.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && action_scope.attributes.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && raw_action.derivation_inputs.len() <= wallet::MAX_HISTORY_ATTRIBUTES,
    )?;
    for name in raw_scope.attributes.iter().chain(&action_scope.attributes) {
        require(!name.is_empty() && name.len() <= MAX_POLICY_IDENTIFIER_BYTES)?;
    }
    let requested = consent_scope_from_proto(p.requested_scope.as_option().ok_or_else(invalid)?)?;
    require(requested.attributes.len() <= wallet::MAX_HISTORY_ATTRIBUTES)?;
    let action = consent_action_from_proto(p.selected_action.as_option().ok_or_else(invalid)?)?;
    require(action.scope.attributes.len() <= wallet::MAX_HISTORY_ATTRIBUTES)?;
    let user = match p.user_decision.as_known().ok_or_else(invalid)? {
        pb::ConsentDecision::CONSENT_DECISION_APPROVED => wallet::ConsentDecision::Approved,
        pb::ConsentDecision::CONSENT_DECISION_REJECTED => wallet::ConsentDecision::Rejected,
        _ => return Err(invalid()),
    };
    Ok(wallet::ConsentCapture {
        relying_party_id: wallet::RelyingPartyId::new(text(&p.relying_party_id)?)
            .map_err(|_| invalid())?,
        requested_scope: requested,
        selected_action: action,
        request_nonce: wallet::NonEmptyIdentifier::new(text(&p.request_nonce)?)
            .map_err(|_| invalid())?,
        request_digest: nonzero(&p.request_digest)?,
        policy_decision: disclosure_policy_decision_from_proto(
            p.policy_decision.as_known().ok_or_else(invalid)?,
        )?,
        user_decision: user,
        captured_at: unix_timestamp_from_proto(p.captured_at.as_option().ok_or_else(invalid)?)?,
    })
}

#[allow(
    clippy::field_reassign_with_default,
    reason = "Generated secret-bearing messages implement Drop and require field-wise construction."
)]
pub(super) fn receipt_to_proto(v: &wallet::ConsentReceipt) -> ProtoResult<pb::ConsentReceipt> {
    let mut p = pb::ConsentReceipt::default();
    p.schema_version = POLICY_SCHEMA_VERSION;
    p.capture = MessageField::some(capture_to_proto(&v.capture)?);
    p.policy = v.policy.as_ref().map(policy_to_proto).transpose()?.into();
    p.reader = v.reader.as_ref().map(reader_to_proto).into();
    Ok(p)
}

pub(super) fn receipt_from_proto(p: &pb::ConsentReceipt) -> ProtoResult<wallet::ConsentReceipt> {
    require(p.schema_version == POLICY_SCHEMA_VERSION)?;
    let capture = capture_from_proto(p.capture.as_option().ok_or_else(invalid)?)?;
    let reader = p.reader.as_option().map(reader_from_proto).transpose()?;
    require(reader.as_ref().is_none_or(|r| {
        r.reader_id == capture.relying_party_id
            && r.authenticated_at <= capture.captured_at
            && capture.captured_at < r.valid_until
    }))?;
    Ok(wallet::ConsentReceipt {
        capture,
        policy: p.policy.as_option().map(policy_from_proto).transpose()?,
        reader,
    })
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn encode_consent_receipt(value: &wallet::ConsentReceipt) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let wire = receipt_to_proto(value)?;
    let _validated = receipt_from_proto(&wire)?;
    encode(&wire)
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn decode_consent_receipt(bytes: &[u8]) -> ProtoResult<wallet::ConsentReceipt> {
    receipt_from_proto(&decode::<pb::ConsentReceipt>(bytes)?)
}
