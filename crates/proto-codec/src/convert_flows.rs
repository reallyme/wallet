// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, EnumValue, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;

use super::{
    known_enum, unix_timestamp_from_proto, unix_timestamp_to_proto, ConvertError,
    ConvertErrorReason, ConvertResult,
};
use crate::limits::{
    MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES, MAX_WALLET_PROTO_MESSAGE_BYTES,
    MAX_WALLET_PROTO_RECURSION_DEPTH, MAX_WALLET_REPEATED_IDENTIFIERS,
    WALLET_PROTO_UNKNOWN_FIELD_LIMIT,
};

/// Convert a validated wallet reuse-policy selection into protobuf.
#[must_use]
pub fn credential_reuse_policy_to_proto(
    selection: &wallet::CredentialReusePolicySelection,
) -> pb::OpenId4VciCredentialReusePolicySelection {
    let method = match selection.method() {
        wallet::CredentialReuseMethod::Unrestricted => {
            pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_UNRESTRICTED
        }
        wallet::CredentialReuseMethod::OnceOnly => {
            pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_ONCE_ONLY
        }
        wallet::CredentialReuseMethod::LimitedTime => {
            pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_LIMITED_TIME
        }
        wallet::CredentialReuseMethod::RotatingBatch => {
            pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_ROTATING_BATCH
        }
        wallet::CredentialReuseMethod::PerRelyingParty => {
            pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_PER_RELYING_PARTY
        }
    };
    let mut result = pb::OpenId4VciCredentialReusePolicySelection::default();
    result.credential_configuration_id =
        selection.credential_configuration_id().as_str().to_owned();
    result.method = EnumValue::from(method);
    result.batch_size = selection.batch_size();
    result.reissue_trigger_unused = selection.reissue_trigger_unused();
    result.reissue_trigger_lifetime_left_seconds =
        selection.reissue_trigger_lifetime_left_seconds();
    result
}
/// Convert and validate a generated reuse-policy selection.
pub fn credential_reuse_policy_from_proto(
    selection: &pb::OpenId4VciCredentialReusePolicySelection,
) -> ConvertResult<wallet::CredentialReusePolicySelection> {
    let method = match known_enum(selection.method)? {
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_UNRESTRICTED => {
            wallet::CredentialReuseMethod::Unrestricted
        }
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_ONCE_ONLY => {
            wallet::CredentialReuseMethod::OnceOnly
        }
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_LIMITED_TIME => {
            wallet::CredentialReuseMethod::LimitedTime
        }
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_ROTATING_BATCH => {
            wallet::CredentialReuseMethod::RotatingBatch
        }
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_PER_RELYING_PARTY => {
            wallet::CredentialReuseMethod::PerRelyingParty
        }
        pb::OpenId4VciCredentialReuseMethod::OPEN_ID4_VCI_CREDENTIAL_REUSE_METHOD_UNSPECIFIED => {
            return Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue));
        }
    };
    wallet::CredentialReusePolicySelection::new(
        wallet::NonEmptyIdentifier::new(selection.credential_configuration_id.clone())?,
        method,
        selection.batch_size,
        selection.reissue_trigger_unused,
        selection.reissue_trigger_lifetime_left_seconds,
    )
    .map_err(Into::into)
}

/// Convert a durable issuer-metadata profile into protobuf.
#[must_use]
pub const fn issuer_metadata_profile_to_proto(
    profile: wallet::OpenId4VciIssuerMetadataProfile,
) -> pb::OpenId4VciIssuerMetadataProfile {
    match profile {
        wallet::OpenId4VciIssuerMetadataProfile::OpenId4Vci => {
            pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_OPENID4VCI
        }
        wallet::OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3 => {
            pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_ETSI_TS_119_472_PART_3
        }
        wallet::OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3 => {
            pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_EU_ETSI_TS_119_472_PART_3
        }
    }
}

/// Convert a known, specified protobuf issuer-metadata profile.
pub fn issuer_metadata_profile_from_proto(
    profile: pb::OpenId4VciIssuerMetadataProfile,
) -> ConvertResult<wallet::OpenId4VciIssuerMetadataProfile> {
    match profile {
        pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_OPENID4VCI => {
            Ok(wallet::OpenId4VciIssuerMetadataProfile::OpenId4Vci)
        }
        pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_ETSI_TS_119_472_PART_3 => {
            Ok(wallet::OpenId4VciIssuerMetadataProfile::EtsiTs119472Part3)
        }
        pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_EU_ETSI_TS_119_472_PART_3 => {
            Ok(wallet::OpenId4VciIssuerMetadataProfile::EuEtsiTs119472Part3)
        }
        pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet flow kind into protobuf.
#[must_use]
pub fn flow_kind_to_proto(kind: wallet::FlowKind) -> pb::FlowKind {
    match kind {
        wallet::FlowKind::Issuance => pb::FlowKind::FLOW_KIND_ISSUANCE,
        wallet::FlowKind::Presentation => pb::FlowKind::FLOW_KIND_PRESENTATION,
    }
}

/// Convert a generated protobuf flow kind into wallet state.
pub fn flow_kind_from_proto(kind: pb::FlowKind) -> ConvertResult<wallet::FlowKind> {
    match kind {
        pb::FlowKind::FLOW_KIND_ISSUANCE => Ok(wallet::FlowKind::Issuance),
        pb::FlowKind::FLOW_KIND_PRESENTATION => Ok(wallet::FlowKind::Presentation),
        pb::FlowKind::FLOW_KIND_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a wallet flow snapshot into protobuf.
#[must_use]
pub fn flow_snapshot_to_proto(snapshot: &wallet::FlowSnapshot) -> pb::FlowSnapshot {
    let mut result = pb::FlowSnapshot::default();
    result.id = snapshot.id.as_str().to_owned();
    result.kind = EnumValue::from(flow_kind_to_proto(snapshot.kind));
    result.state = snapshot.state.clone();
    result.updated_at = MessageField::some(unix_timestamp_to_proto(snapshot.updated_at));
    result.state_schema_version = snapshot.state_schema_version.as_u32();
    result
}

/// Convert a generated protobuf flow snapshot into wallet state.
pub fn flow_snapshot_from_proto(
    snapshot: &pb::FlowSnapshot,
) -> ConvertResult<wallet::FlowSnapshot> {
    let updated_at = snapshot
        .updated_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;

    let state_schema_version = match snapshot.state_schema_version {
        1 => wallet::FlowStateSchemaVersion::V1,
        _ => {
            return Err(ConvertError::new(
                ConvertErrorReason::UnsupportedFlowStateSchemaVersion,
            ));
        }
    };

    let kind = flow_kind_from_proto(known_enum(snapshot.kind)?)?;
    validate_flow_state_payload(kind, &snapshot.state)?;

    Ok(wallet::FlowSnapshot {
        id: wallet::FlowSnapshotId::new(snapshot.id.clone())?,
        kind,
        state: snapshot.state.clone(),
        state_schema_version,
        updated_at,
    })
}

fn validate_flow_state_payload(kind: wallet::FlowKind, state: &[u8]) -> ConvertResult<()> {
    match kind {
        wallet::FlowKind::Issuance => {
            let decoded: pb::OpenId4VciIssuanceSnapshot = DecodeOptions::new()
                .with_recursion_limit(MAX_WALLET_PROTO_RECURSION_DEPTH)
                .with_max_message_size(MAX_WALLET_PROTO_MESSAGE_BYTES)
                .with_element_memory_limit(MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES)
                .with_unknown_field_limit(WALLET_PROTO_UNKNOWN_FIELD_LIMIT)
                .decode_from_slice(state)
                .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
            match decoded.stage.as_known() {
                Some(pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_UNSPECIFIED)
                | None => Err(ConvertError::new(
                    ConvertErrorReason::InvalidFlowStatePayload,
                )),
                Some(
                    pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CREDENTIAL_STORED,
                ) => validate_stored_issuance_snapshot(&decoded),
                Some(stage) => validate_non_stored_issuance_snapshot(&decoded, stage),
            }
        }
        wallet::FlowKind::Presentation => {
            let decoded: pb::OpenId4VpPresentationSnapshot = DecodeOptions::new()
                .with_recursion_limit(MAX_WALLET_PROTO_RECURSION_DEPTH)
                .with_max_message_size(MAX_WALLET_PROTO_MESSAGE_BYTES)
                .with_element_memory_limit(MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES)
                .with_unknown_field_limit(WALLET_PROTO_UNKNOWN_FIELD_LIMIT)
                .decode_from_slice(state)
                .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
            // Each stage requires the ones before it: a verified request, then
            // a selection of query and credentials, then consent, then the
            // response. A snapshot holding a later stage alone is malformed.
            let selected =
                !decoded.selected_query_id.is_empty() && !decoded.credential_record_ids.is_empty();
            let selection_consistent = selected
                == (!decoded.selected_query_id.is_empty()
                    || !decoded.credential_record_ids.is_empty());
            if decoded.authorization_request.is_set()
                && selection_consistent
                && decoded.credential_record_ids.len() <= MAX_WALLET_REPEATED_IDENTIFIERS
                && (!decoded.consent.is_set() || selected)
                && (!decoded.authorization_response.is_set() || decoded.consent.is_set())
            {
                Ok(())
            } else {
                Err(ConvertError::new(
                    ConvertErrorReason::InvalidFlowStatePayload,
                ))
            }
        }
    }
}

fn validate_stored_issuance_snapshot(
    snapshot: &pb::OpenId4VciIssuanceSnapshot,
) -> ConvertResult<()> {
    validate_issuer_metadata_profile(snapshot)?;
    if let Some(nonce) = snapshot.issuer_nonce_binding.as_option() {
        issuer_nonce_binding_from_proto(nonce)?;
    }
    validate_credential_reuse_policy(snapshot)?;
    let v1_single = !snapshot.credential_record_id.is_empty();
    let canonical = !snapshot.credential_record_ids.is_empty();
    if snapshot.credential_record_ids.len() > MAX_WALLET_REPEATED_IDENTIFIERS {
        return Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    let duplicate_canonical_id = snapshot
        .credential_record_ids
        .iter()
        .any(|id| id.is_empty() || !ids.insert(id.as_str()));
    let has_notification_id = !snapshot.notification_id.is_empty();
    let has_notification_endpoint = !snapshot.notification_endpoint.is_empty();
    let has_token_handle = !snapshot.access_token_binding_handle.is_empty();
    let v1_single_without_binding_key =
        v1_single && snapshot.credential_binding_key_handle_ids.is_empty();
    let binding_keys_are_valid =
        v1_single_without_binding_key || valid_credential_binding_keys(snapshot);
    let canonical_minimized_state = canonical
        && !snapshot.credential_request.is_set()
        && !snapshot.credential_response.is_set()
        && !snapshot.wallet_unit_attestation.is_set();
    let v1_evidenceful_state = v1_single
        && !snapshot.credential_request.is_set()
        && snapshot.credential_response.is_set()
        && snapshot.wallet_unit_attestation.is_set();
    if v1_single == canonical
        || duplicate_canonical_id
        || !binding_keys_are_valid
        || canonical
            && snapshot.credential_binding_key_handle_ids.len()
                != snapshot.credential_record_ids.len()
        || v1_single && snapshot.credential_binding_key_handle_ids.len() > 1
        || has_notification_id != has_notification_endpoint
        || (has_notification_id && !has_token_handle)
        || !snapshot.credential_offer.is_set()
        || !(canonical_minimized_state || v1_evidenceful_state)
        || !snapshot.deferred_transaction_id.is_empty()
        || snapshot.deferred_interval_seconds != 0
        || !has_token_handle
    {
        return Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ));
    }
    Ok(())
}

fn validate_non_stored_issuance_snapshot(
    snapshot: &pb::OpenId4VciIssuanceSnapshot,
    stage: pb::OpenId4VciIssuanceStage,
) -> ConvertResult<()> {
    validate_issuer_metadata_profile(snapshot)?;
    if let Some(nonce) = snapshot.issuer_nonce_binding.as_option() {
        issuer_nonce_binding_from_proto(nonce)?;
    }
    validate_credential_reuse_policy(snapshot)?;
    if !snapshot.credential_offer.is_set()
        || !snapshot.credential_record_id.is_empty()
        || !snapshot.credential_record_ids.is_empty()
    {
        return Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ));
    }
    let valid = match stage {
        pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_OFFER_RECEIVED
        | pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CONSENT_CAPTURED
        | pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_AUTHORIZED => {
            !snapshot.credential_request.is_set()
                && !snapshot.credential_response.is_set()
                && snapshot.credential_binding_key_handle_ids.is_empty()
                && snapshot.deferred_transaction_id.is_empty()
                && snapshot.deferred_interval_seconds == 0
        }
        pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_TOKEN_EXCHANGED => {
            snapshot.wallet_unit_attestation.is_set()
                && !snapshot.access_token_binding_handle.is_empty()
                && snapshot.credential_binding_key_handle_ids.is_empty()
                && snapshot.deferred_transaction_id.is_empty()
                && snapshot.deferred_interval_seconds == 0
        }
        pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_DEFERRED => {
            snapshot.credential_request.is_set()
                && snapshot.credential_response.is_set()
                && snapshot.wallet_unit_attestation.is_set()
                && !snapshot.access_token_binding_handle.is_empty()
                && valid_credential_binding_keys(snapshot)
                && !snapshot.deferred_transaction_id.is_empty()
                && snapshot.deferred_interval_seconds > 0
                && snapshot.deferred_interval_seconds <= 86_400
        }
        pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CREDENTIAL_RECEIVED => {
            snapshot.credential_request.is_set()
                && snapshot.credential_response.is_set()
                && snapshot.wallet_unit_attestation.is_set()
                && !snapshot.access_token_binding_handle.is_empty()
                && valid_credential_binding_keys(snapshot)
                && snapshot.deferred_transaction_id.is_empty()
                && snapshot.deferred_interval_seconds == 0
        }
        pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CREDENTIAL_STORED
        | pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_UNSPECIFIED => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ))
    }
}

fn validate_credential_reuse_policy(
    snapshot: &pb::OpenId4VciIssuanceSnapshot,
) -> ConvertResult<()> {
    let Some(selection) = snapshot.credential_reuse_policy.as_option() else {
        // V1 snapshots written before reuse-policy support are unrestricted.
        return Ok(());
    };
    let offered = snapshot.credential_offer.as_option().is_some_and(|offer| {
        offer
            .credential_configuration_ids
            .iter()
            .any(|identifier| identifier == &selection.credential_configuration_id)
    });
    if selection.credential_configuration_id.is_empty() || !offered {
        return Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ));
    }
    if snapshot
        .credential_request
        .as_option()
        .is_some_and(|request| {
            request
                .selector
                .as_option()
                .and_then(|selector| selector.selector.as_ref())
                .is_some_and(|selector| {
                    matches!(
                        selector,
                        openid4vci_pb::credential_selector::Selector::CredentialConfigurationId(
                            identifier
                        ) if identifier != &selection.credential_configuration_id
                    )
                })
        })
    {
        return Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ));
    }

    credential_reuse_policy_from_proto(selection)
        .map(|_| ())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))
}

fn validate_issuer_metadata_profile(
    snapshot: &pb::OpenId4VciIssuanceSnapshot,
) -> ConvertResult<()> {
    match snapshot.issuer_metadata_profile.as_known() {
        // V1 snapshots written before profile persistence used zero and are
        // necessarily generic OpenID4VCI because no ETSI lane existed.
        Some(
            pb::OpenId4VciIssuerMetadataProfile::OPEN_ID4_VCI_ISSUER_METADATA_PROFILE_UNSPECIFIED,
        ) => Ok(()),
        Some(profile) => issuer_metadata_profile_from_proto(profile)
            .map(|_| ())
            .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload)),
        None => Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        )),
    }
}

fn valid_credential_binding_keys(snapshot: &pb::OpenId4VciIssuanceSnapshot) -> bool {
    if snapshot.credential_binding_key_handle_ids.is_empty()
        || snapshot.credential_binding_key_handle_ids.len() > MAX_WALLET_REPEATED_IDENTIFIERS
    {
        return false;
    }
    let mut handles = std::collections::BTreeSet::new();
    snapshot
        .credential_binding_key_handle_ids
        .iter()
        .all(|handle| !handle.is_empty() && handles.insert(handle.as_str()))
}

/// Encode the retained nonce observation without plaintext nonce bytes.
pub fn issuer_nonce_binding_to_proto(
    binding: &wallet::IssuerNonceBinding,
) -> pb::IssuerNonceBinding {
    let mut result = pb::IssuerNonceBinding::default();
    result.nonce_digest = binding.nonce_digest.to_vec();
    result.session_digest = binding.session_digest.to_vec();
    result.received_at = binding.received_at.as_seconds();
    result.expires_at = binding.expires_at.as_seconds();
    result
}
/// Decode bounded nonce observation shape; the flow owner verifies session and proof binding.
pub fn issuer_nonce_binding_from_proto(
    binding: &pb::IssuerNonceBinding,
) -> ConvertResult<wallet::IssuerNonceBinding> {
    let nonce_digest = <[u8; 32]>::try_from(binding.nonce_digest.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    let session_digest = <[u8; 32]>::try_from(binding.session_digest.as_slice())
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidFlowStatePayload))?;
    let received_at = wallet::UnixTimestamp::from_seconds(binding.received_at)?;
    let expires_at = wallet::UnixTimestamp::from_seconds(binding.expires_at)?;
    if nonce_digest == [0; 32] || session_digest == [0; 32] || expires_at <= received_at {
        return Err(ConvertError::new(
            ConvertErrorReason::InvalidFlowStatePayload,
        ));
    }
    Ok(wallet::IssuerNonceBinding {
        nonce_digest,
        session_digest,
        received_at,
        expires_at,
    })
}

#[cfg(test)]
#[path = "convert_flows_tests.rs"]
mod tests;
