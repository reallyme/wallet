// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded canonical codec record conversion.

use crate::{ProtoError, ProtoErrorReason, ProtoResult};
use buffa::{DecodeOptions, EnumValue, Message};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

use super::MAX_POLICY_RECORD_BYTES;
pub(super) const MAX_POLICY_IDENTIFIER_BYTES: usize = 256;
pub(super) const POLICY_SCHEMA_VERSION: u32 = 1;
pub(super) const HISTORY_SCHEMA_VERSION: u32 = 2;
pub(super) const POLICY_RECURSION_LIMIT: u32 = 8;

pub(super) fn invalid() -> ProtoError {
    ProtoError::new(ProtoErrorReason::InvalidDto)
}

pub(super) fn require(condition: bool) -> ProtoResult<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) fn fixed(bytes: &[u8]) -> ProtoResult<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| invalid())
}

pub(super) fn nonzero(bytes: &[u8]) -> ProtoResult<[u8; 32]> {
    let value = fixed(bytes)?;
    require(value != [0; 32])?;
    Ok(value)
}

pub(super) fn optional_digest(bytes: &[u8]) -> ProtoResult<Option<[u8; 32]>> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(nonzero(bytes)?))
    }
}

pub(super) fn text(value: &str) -> ProtoResult<String> {
    require(!value.is_empty() && value.len() <= MAX_POLICY_IDENTIFIER_BYTES)?;
    Ok(value.to_owned())
}
pub(super) fn timestamp(value: i64) -> ProtoResult<wallet::UnixTimestamp> {
    require(value > 0)?;
    wallet::UnixTimestamp::from_seconds(value).map_err(|_| invalid())
}

pub(super) fn encode<M: Message>(message: &M) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let length = message.try_encoded_len().map_err(|_| invalid())?;
    let max = u32::try_from(MAX_POLICY_RECORD_BYTES).map_err(|_| invalid())?;
    require(length <= max)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(usize::try_from(length).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    message
        .try_encode_bounded(max, &mut *bytes)
        .map_err(|_| invalid())?;
    Ok(bytes)
}

pub(super) fn decode<M: Message>(bytes: &[u8]) -> ProtoResult<M> {
    if bytes.len() > MAX_POLICY_RECORD_BYTES {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }
    let message = DecodeOptions::new()
        .with_max_message_size(MAX_POLICY_RECORD_BYTES)
        .with_recursion_limit(POLICY_RECURSION_LIMIT)
        .with_element_memory_limit(MAX_POLICY_RECORD_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<M>(bytes)
        .map_err(ProtoError::from)?;
    require(encode(&message)?.as_slice() == bytes)?;
    Ok(message)
}

pub(super) fn history_purpose_to_proto(
    value: wallet::HistoryPurpose,
) -> EnumValue<pb::HistoryPurpose> {
    EnumValue::from(match value {
        wallet::HistoryPurpose::Issuance => pb::HistoryPurpose::HISTORY_PURPOSE_ISSUANCE,
        wallet::HistoryPurpose::Presentation => pb::HistoryPurpose::HISTORY_PURPOSE_PRESENTATION,
        wallet::HistoryPurpose::Refresh => pb::HistoryPurpose::HISTORY_PURPOSE_REFRESH,
        wallet::HistoryPurpose::Deletion => pb::HistoryPurpose::HISTORY_PURPOSE_DELETION,
        wallet::HistoryPurpose::QualifiedSignature => {
            pb::HistoryPurpose::HISTORY_PURPOSE_QUALIFIED_SIGNATURE
        }
        wallet::HistoryPurpose::QualifiedSeal => pb::HistoryPurpose::HISTORY_PURPOSE_QUALIFIED_SEAL,
    })
}

pub(super) fn history_purpose_from_proto(
    value: EnumValue<pb::HistoryPurpose>,
) -> ProtoResult<wallet::HistoryPurpose> {
    match value.as_known().ok_or_else(invalid)? {
        pb::HistoryPurpose::HISTORY_PURPOSE_ISSUANCE => Ok(wallet::HistoryPurpose::Issuance),
        pb::HistoryPurpose::HISTORY_PURPOSE_PRESENTATION => {
            Ok(wallet::HistoryPurpose::Presentation)
        }
        pb::HistoryPurpose::HISTORY_PURPOSE_REFRESH => Ok(wallet::HistoryPurpose::Refresh),
        pb::HistoryPurpose::HISTORY_PURPOSE_DELETION => Ok(wallet::HistoryPurpose::Deletion),
        pb::HistoryPurpose::HISTORY_PURPOSE_QUALIFIED_SIGNATURE => {
            Ok(wallet::HistoryPurpose::QualifiedSignature)
        }
        pb::HistoryPurpose::HISTORY_PURPOSE_QUALIFIED_SEAL => {
            Ok(wallet::HistoryPurpose::QualifiedSeal)
        }
        pb::HistoryPurpose::HISTORY_PURPOSE_UNSPECIFIED => Err(invalid()),
    }
}

pub(super) fn history_outcome_to_proto(
    value: wallet::HistoryOutcome,
) -> EnumValue<pb::HistoryOutcome> {
    EnumValue::from(match value {
        wallet::HistoryOutcome::Completed => pb::HistoryOutcome::HISTORY_OUTCOME_COMPLETED,
        wallet::HistoryOutcome::Refused => pb::HistoryOutcome::HISTORY_OUTCOME_REFUSED,
        wallet::HistoryOutcome::Cancelled => pb::HistoryOutcome::HISTORY_OUTCOME_CANCELLED,
        wallet::HistoryOutcome::Failed => pb::HistoryOutcome::HISTORY_OUTCOME_FAILED,
        wallet::HistoryOutcome::Expired => pb::HistoryOutcome::HISTORY_OUTCOME_EXPIRED,
        wallet::HistoryOutcome::DeliveryUnknown => {
            pb::HistoryOutcome::HISTORY_OUTCOME_DELIVERY_UNKNOWN
        }
    })
}

pub(super) fn history_outcome_from_proto(
    value: EnumValue<pb::HistoryOutcome>,
) -> ProtoResult<wallet::HistoryOutcome> {
    match value.as_known().ok_or_else(invalid)? {
        pb::HistoryOutcome::HISTORY_OUTCOME_COMPLETED => Ok(wallet::HistoryOutcome::Completed),
        pb::HistoryOutcome::HISTORY_OUTCOME_REFUSED => Ok(wallet::HistoryOutcome::Refused),
        pb::HistoryOutcome::HISTORY_OUTCOME_CANCELLED => Ok(wallet::HistoryOutcome::Cancelled),
        pb::HistoryOutcome::HISTORY_OUTCOME_FAILED => Ok(wallet::HistoryOutcome::Failed),
        pb::HistoryOutcome::HISTORY_OUTCOME_EXPIRED => Ok(wallet::HistoryOutcome::Expired),
        pb::HistoryOutcome::HISTORY_OUTCOME_DELIVERY_UNKNOWN => {
            Ok(wallet::HistoryOutcome::DeliveryUnknown)
        }
        pb::HistoryOutcome::HISTORY_OUTCOME_UNSPECIFIED => Err(invalid()),
    }
}

pub(super) fn history_failure_reason_to_proto(
    value: wallet::HistoryFailureReason,
) -> EnumValue<pb::HistoryFailureReason> {
    EnumValue::from(match value {
        wallet::HistoryFailureReason::None => pb::HistoryFailureReason::HISTORY_FAILURE_REASON_NONE,
        wallet::HistoryFailureReason::UserDecision => {
            pb::HistoryFailureReason::HISTORY_FAILURE_REASON_USER_DECISION
        }
        wallet::HistoryFailureReason::Policy => {
            pb::HistoryFailureReason::HISTORY_FAILURE_REASON_POLICY
        }
        wallet::HistoryFailureReason::InvalidInput => {
            pb::HistoryFailureReason::HISTORY_FAILURE_REASON_INVALID_INPUT
        }
        wallet::HistoryFailureReason::Provider => {
            pb::HistoryFailureReason::HISTORY_FAILURE_REASON_PROVIDER
        }
        wallet::HistoryFailureReason::Transport => {
            pb::HistoryFailureReason::HISTORY_FAILURE_REASON_TRANSPORT
        }
        wallet::HistoryFailureReason::Expiry => {
            pb::HistoryFailureReason::HISTORY_FAILURE_REASON_EXPIRY
        }
    })
}

pub(super) fn history_failure_reason_from_proto(
    value: EnumValue<pb::HistoryFailureReason>,
) -> ProtoResult<wallet::HistoryFailureReason> {
    match value.as_known().ok_or_else(invalid)? {
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_NONE => {
            Ok(wallet::HistoryFailureReason::None)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_USER_DECISION => {
            Ok(wallet::HistoryFailureReason::UserDecision)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_POLICY => {
            Ok(wallet::HistoryFailureReason::Policy)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_INVALID_INPUT => {
            Ok(wallet::HistoryFailureReason::InvalidInput)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_PROVIDER => {
            Ok(wallet::HistoryFailureReason::Provider)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_TRANSPORT => {
            Ok(wallet::HistoryFailureReason::Transport)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_EXPIRY => {
            Ok(wallet::HistoryFailureReason::Expiry)
        }
        pb::HistoryFailureReason::HISTORY_FAILURE_REASON_UNSPECIFIED => Err(invalid()),
    }
}

pub(super) fn flow_disposition_to_proto(
    value: wallet::FlowDisposition,
) -> EnumValue<pb::FlowDisposition> {
    EnumValue::from(match value {
        wallet::FlowDisposition::Active => pb::FlowDisposition::FLOW_DISPOSITION_ACTIVE,
        wallet::FlowDisposition::Completed => pb::FlowDisposition::FLOW_DISPOSITION_COMPLETED,
        wallet::FlowDisposition::Cancelled => pb::FlowDisposition::FLOW_DISPOSITION_CANCELLED,
        wallet::FlowDisposition::Failed => pb::FlowDisposition::FLOW_DISPOSITION_FAILED,
        wallet::FlowDisposition::Expired => pb::FlowDisposition::FLOW_DISPOSITION_EXPIRED,
        wallet::FlowDisposition::DeliveryUnknown => {
            pb::FlowDisposition::FLOW_DISPOSITION_DELIVERY_UNKNOWN
        }
    })
}

pub(super) fn flow_disposition_from_proto(
    value: EnumValue<pb::FlowDisposition>,
) -> ProtoResult<wallet::FlowDisposition> {
    match value.as_known().ok_or_else(invalid)? {
        pb::FlowDisposition::FLOW_DISPOSITION_ACTIVE => Ok(wallet::FlowDisposition::Active),
        pb::FlowDisposition::FLOW_DISPOSITION_COMPLETED => Ok(wallet::FlowDisposition::Completed),
        pb::FlowDisposition::FLOW_DISPOSITION_CANCELLED => Ok(wallet::FlowDisposition::Cancelled),
        pb::FlowDisposition::FLOW_DISPOSITION_FAILED => Ok(wallet::FlowDisposition::Failed),
        pb::FlowDisposition::FLOW_DISPOSITION_EXPIRED => Ok(wallet::FlowDisposition::Expired),
        pb::FlowDisposition::FLOW_DISPOSITION_DELIVERY_UNKNOWN => {
            Ok(wallet::FlowDisposition::DeliveryUnknown)
        }
        pb::FlowDisposition::FLOW_DISPOSITION_UNSPECIFIED => Err(invalid()),
    }
}

pub(super) fn flow_effect_kind_to_proto(
    value: wallet::FlowEffectKind,
) -> EnumValue<pb::FlowEffectKind> {
    EnumValue::from(match value {
        wallet::FlowEffectKind::Consent => pb::FlowEffectKind::FLOW_EFFECT_KIND_CONSENT,
        wallet::FlowEffectKind::Signing => pb::FlowEffectKind::FLOW_EFFECT_KIND_SIGNING,
        wallet::FlowEffectKind::Submission => pb::FlowEffectKind::FLOW_EFFECT_KIND_SUBMISSION,
        wallet::FlowEffectKind::StorageCommit => {
            pb::FlowEffectKind::FLOW_EFFECT_KIND_STORAGE_COMMIT
        }
    })
}

pub(super) fn flow_effect_kind_from_proto(
    value: EnumValue<pb::FlowEffectKind>,
) -> ProtoResult<wallet::FlowEffectKind> {
    match value.as_known().ok_or_else(invalid)? {
        pb::FlowEffectKind::FLOW_EFFECT_KIND_CONSENT => Ok(wallet::FlowEffectKind::Consent),
        pb::FlowEffectKind::FLOW_EFFECT_KIND_SIGNING => Ok(wallet::FlowEffectKind::Signing),
        pb::FlowEffectKind::FLOW_EFFECT_KIND_SUBMISSION => Ok(wallet::FlowEffectKind::Submission),
        pb::FlowEffectKind::FLOW_EFFECT_KIND_STORAGE_COMMIT => {
            Ok(wallet::FlowEffectKind::StorageCommit)
        }
        pb::FlowEffectKind::FLOW_EFFECT_KIND_UNSPECIFIED => Err(invalid()),
    }
}

pub(super) fn flow_effect_state_to_proto(
    value: wallet::FlowEffectState,
) -> EnumValue<pb::FlowEffectState> {
    EnumValue::from(match value {
        wallet::FlowEffectState::Reserved => pb::FlowEffectState::FLOW_EFFECT_STATE_RESERVED,
        wallet::FlowEffectState::Confirmed => pb::FlowEffectState::FLOW_EFFECT_STATE_CONFIRMED,
    })
}

pub(super) fn flow_effect_state_from_proto(
    value: EnumValue<pb::FlowEffectState>,
) -> ProtoResult<wallet::FlowEffectState> {
    match value.as_known().ok_or_else(invalid)? {
        pb::FlowEffectState::FLOW_EFFECT_STATE_RESERVED => Ok(wallet::FlowEffectState::Reserved),
        pb::FlowEffectState::FLOW_EFFECT_STATE_CONFIRMED => Ok(wallet::FlowEffectState::Confirmed),
        pb::FlowEffectState::FLOW_EFFECT_STATE_UNSPECIFIED => Err(invalid()),
    }
}
