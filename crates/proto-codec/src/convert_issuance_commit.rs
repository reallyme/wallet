// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Convert atomic OpenID4VCI issuance commits and notification outbox entries.

use buffa::{DecodeOptions, EnumValue, Message, MessageField};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::{known_enum, ConvertError, ConvertErrorReason, ConvertResult};
use crate::convert::{
    credential_record_from_proto, credential_record_to_proto, flow_snapshot_from_proto,
    flow_snapshot_to_proto, unix_timestamp_from_proto, unix_timestamp_to_proto,
};
use crate::limits::{
    MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES, MAX_WALLET_PROTO_MESSAGE_BYTES,
    MAX_WALLET_PROTO_RECURSION_DEPTH, MAX_WALLET_REPEATED_IDENTIFIERS,
    WALLET_PROTO_UNKNOWN_FIELD_LIMIT,
};

/// Validated, internally consistent atomic issuance completion aggregate.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct OpenId4VciIssuanceCommit {
    idempotency_key: [u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
    request_digest: [u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
    credential_records: Vec<wallet::CredentialRecord>,
    flow_snapshot: wallet::FlowSnapshot,
    notification_outbox: Option<wallet::OpenId4VciNotificationOutboxEntry>,
}

impl OpenId4VciIssuanceCommit {
    /// Borrow the fixed idempotency key used by the atomic storage provider.
    #[must_use]
    pub const fn idempotency_key(&self) -> &[u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES] {
        &self.idempotency_key
    }

    /// Borrow the digest of the complete canonical commit request.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES] {
        &self.request_digest
    }

    /// Borrow each independently selectable credential record.
    #[must_use]
    pub fn credential_records(&self) -> &[wallet::CredentialRecord] {
        &self.credential_records
    }

    /// Borrow the stored-stage flow snapshot.
    #[must_use]
    pub const fn flow_snapshot(&self) -> &wallet::FlowSnapshot {
        &self.flow_snapshot
    }

    /// Borrow pending notification work, when the issuer requested it.
    #[must_use]
    pub const fn notification_outbox(&self) -> Option<&wallet::OpenId4VciNotificationOutboxEntry> {
        self.notification_outbox.as_ref()
    }
}

/// Convert a notification delivery state into protobuf.
#[must_use]
pub const fn notification_delivery_state_to_proto(
    state: wallet::OpenId4VciNotificationDeliveryState,
) -> pb::OpenId4VciNotificationDeliveryState {
    match state {
        wallet::OpenId4VciNotificationDeliveryState::Pending => {
            pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_PENDING
        }
        wallet::OpenId4VciNotificationDeliveryState::Delivered => {
            pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_DELIVERED
        }
    }
}

/// Convert a generated notification delivery state into wallet state.
pub const fn notification_delivery_state_from_proto(
    state: pb::OpenId4VciNotificationDeliveryState,
) -> ConvertResult<wallet::OpenId4VciNotificationDeliveryState> {
    match state {
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_PENDING => {
            Ok(wallet::OpenId4VciNotificationDeliveryState::Pending)
        }
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_DELIVERED => {
            Ok(wallet::OpenId4VciNotificationDeliveryState::Delivered)
        }
        pb::OpenId4VciNotificationDeliveryState::OPEN_ID4_VCI_NOTIFICATION_DELIVERY_STATE_UNSPECIFIED => {
            Err(ConvertError::new(ConvertErrorReason::InvalidEnumValue))
        }
    }
}

/// Convert a durable notification outbox entry into protobuf.
#[must_use]
pub fn notification_outbox_to_proto(
    entry: &wallet::OpenId4VciNotificationOutboxEntry,
) -> pb::OpenId4VciNotificationOutboxEntry {
    let mut result = pb::OpenId4VciNotificationOutboxEntry::default();
    result.credential_issuer = entry.credential_issuer.as_str().to_owned();
    result.notification_id = entry.notification_id.as_str().to_owned();
    result.notification_endpoint = entry.notification_endpoint.as_str().to_owned();
    result.access_token_binding_handle = entry.access_token_binding_handle.as_str().to_owned();
    result.delivery_state =
        EnumValue::from(notification_delivery_state_to_proto(entry.delivery_state));
    result.delivery_attempts = entry.delivery_attempts;
    result.updated_at = MessageField::some(unix_timestamp_to_proto(entry.updated_at));
    result
}

/// Convert and validate a generated durable notification outbox entry.
pub fn notification_outbox_from_proto(
    entry: &pb::OpenId4VciNotificationOutboxEntry,
) -> ConvertResult<wallet::OpenId4VciNotificationOutboxEntry> {
    let updated_at = entry
        .updated_at
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(unix_timestamp_from_proto)?;
    Ok(wallet::OpenId4VciNotificationOutboxEntry {
        credential_issuer: wallet::SignedCredentialIssuer::new(entry.credential_issuer.clone())?,
        notification_id: wallet::NonEmptyIdentifier::new(entry.notification_id.clone())?,
        notification_endpoint: wallet::OpenId4VciNotificationEndpoint::new(
            entry.notification_endpoint.clone(),
            &entry.credential_issuer,
        )?,
        access_token_binding_handle: wallet::NonEmptyIdentifier::new(
            entry.access_token_binding_handle.clone(),
        )?,
        delivery_state: notification_delivery_state_from_proto(known_enum(entry.delivery_state)?)?,
        delivery_attempts: entry.delivery_attempts,
        updated_at,
    })
}

/// Convert an atomic issuance commit into protobuf.
#[must_use]
pub fn issuance_commit_to_proto(commit: &OpenId4VciIssuanceCommit) -> pb::OpenId4VciIssuanceCommit {
    let mut result = canonical_issuance_commit_to_proto(commit);
    result.request_digest = commit.request_digest().to_vec();
    result
}

fn canonical_issuance_commit_to_proto(
    commit: &OpenId4VciIssuanceCommit,
) -> pb::OpenId4VciIssuanceCommit {
    let mut result = pb::OpenId4VciIssuanceCommit::default();
    result.idempotency_key = commit.idempotency_key().to_vec();
    result.credential_records = commit
        .credential_records()
        .iter()
        .map(credential_record_to_proto)
        .collect();
    result.flow_snapshot = MessageField::some(flow_snapshot_to_proto(commit.flow_snapshot()));
    result.notification_outbox = commit
        .notification_outbox()
        .map(notification_outbox_to_proto)
        .into();
    result
}

/// Convert and validate a generated atomic issuance commit.
pub fn issuance_commit_from_proto(
    commit: &pb::OpenId4VciIssuanceCommit,
) -> ConvertResult<OpenId4VciIssuanceCommit> {
    let idempotency_key = <[u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES]>::try_from(
        commit.idempotency_key.as_slice(),
    )
    .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIdempotencyKey))?;
    let request_digest = Zeroizing::new(
        <[u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES]>::try_from(
            commit.request_digest.as_slice(),
        )
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIdempotencyKey))?,
    );
    let credential_records = commit
        .credential_records
        .iter()
        .map(credential_record_from_proto)
        .collect::<ConvertResult<Vec<_>>>()?;
    let flow_snapshot = commit
        .flow_snapshot
        .as_option()
        .ok_or(ConvertError::new(ConvertErrorReason::MissingRequiredField))
        .and_then(flow_snapshot_from_proto)?;
    let notification_outbox = commit
        .notification_outbox
        .as_option()
        .map(notification_outbox_from_proto)
        .transpose()?;
    let validated = build_openid4vci_issuance_commit(
        idempotency_key,
        credential_records,
        flow_snapshot,
        notification_outbox,
    )?;
    if validated.request_digest() != &*request_digest {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIdempotencyKey));
    }
    Ok(validated)
}

/// Build and validate the only aggregate accepted by atomic issuance storage.
pub fn build_openid4vci_issuance_commit(
    idempotency_key: [u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
    credential_records: Vec<wallet::CredentialRecord>,
    flow_snapshot: wallet::FlowSnapshot,
    notification_outbox: Option<wallet::OpenId4VciNotificationOutboxEntry>,
) -> ConvertResult<OpenId4VciIssuanceCommit> {
    if idempotency_key.iter().all(|byte| *byte == 0) {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIdempotencyKey));
    }
    if credential_records.is_empty()
        || credential_records.len() > MAX_WALLET_REPEATED_IDENTIFIERS
        || flow_snapshot.kind != wallet::FlowKind::Issuance
        || {
            let mut ids = std::collections::BTreeSet::new();
            credential_records
                .iter()
                .any(|record| !ids.insert(record.id.as_str()))
        }
    {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit));
    }
    validate_snapshot_binding(
        &flow_snapshot,
        &credential_records,
        notification_outbox.as_ref(),
    )?;
    let mut commit = OpenId4VciIssuanceCommit {
        idempotency_key,
        request_digest: [0; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES],
        credential_records,
        flow_snapshot,
        notification_outbox,
    };
    commit.request_digest = canonical_issuance_commit_digest(&commit)?;
    Ok(commit)
}

fn canonical_issuance_commit_digest(
    commit: &OpenId4VciIssuanceCommit,
) -> ConvertResult<[u8; wallet::OPENID4VCI_ISSUANCE_IDEMPOTENCY_BYTES]> {
    // Omit the digest itself to avoid a circular commitment. The generated
    // message wipes each cloned credential and snapshot when it is dropped.
    let canonical = canonical_issuance_commit_to_proto(commit);
    let encoded_len = canonical
        .try_encoded_len()
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    let max_bytes = u32::try_from(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    if encoded_len > max_bytes {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit));
    }
    let capacity = usize::try_from(encoded_len)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    canonical
        .try_encode_bounded(max_bytes, &mut *encoded)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    Ok(crypto_sha2_256::digest(&encoded).into_bytes())
}

fn validate_snapshot_binding(
    flow_snapshot: &wallet::FlowSnapshot,
    credential_records: &[wallet::CredentialRecord],
    notification_outbox: Option<&wallet::OpenId4VciNotificationOutboxEntry>,
) -> ConvertResult<()> {
    let snapshot: pb::OpenId4VciIssuanceSnapshot = DecodeOptions::new()
        .with_recursion_limit(MAX_WALLET_PROTO_RECURSION_DEPTH)
        .with_max_message_size(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .with_element_memory_limit(MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES)
        .with_unknown_field_limit(WALLET_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(&flow_snapshot.state)
        .map_err(|_| ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
    if snapshot.stage.as_known()
        != Some(pb::OpenId4VciIssuanceStage::OPEN_ID4_VCI_ISSUANCE_STAGE_CREDENTIAL_STORED)
    {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit));
    }
    let record_ids = credential_records
        .iter()
        .map(|record| record.id.as_str())
        .collect::<Vec<_>>();
    if snapshot.credential_record_ids.is_empty() {
        if record_ids.len() != 1 || snapshot.credential_record_id != record_ids[0] {
            return Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit));
        }
    } else if !snapshot.credential_record_id.is_empty()
        || snapshot.credential_record_ids.len() != record_ids.len()
        || snapshot.credential_binding_key_handle_ids.len() != credential_records.len()
        || snapshot
            .credential_record_ids
            .iter()
            .zip(record_ids)
            .any(|(snapshot_id, record_id)| snapshot_id != record_id)
        || !holder_key_sets_match(
            &snapshot.credential_binding_key_handle_ids,
            credential_records,
        )
    {
        return Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit));
    }
    validate_notification_binding(&snapshot, flow_snapshot.updated_at, notification_outbox)
}

fn holder_key_sets_match(
    snapshot_handles: &[String],
    credential_records: &[wallet::CredentialRecord],
) -> bool {
    if snapshot_handles.len() != credential_records.len() {
        return false;
    }
    let expected = snapshot_handles
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if expected.len() != snapshot_handles.len() {
        return false;
    }
    let mut actual = std::collections::BTreeSet::new();
    for record in credential_records {
        let Some(handle) = record.holder_key_handle_id.as_ref() else {
            return false;
        };
        if !actual.insert(handle.as_str()) {
            return false;
        }
    }
    actual == expected
}

fn validate_notification_binding(
    snapshot: &pb::OpenId4VciIssuanceSnapshot,
    updated_at: wallet::UnixTimestamp,
    notification_outbox: Option<&wallet::OpenId4VciNotificationOutboxEntry>,
) -> ConvertResult<()> {
    match notification_outbox {
        None if snapshot.notification_id.is_empty()
            && snapshot.notification_endpoint.is_empty()
            && (snapshot.access_token_binding_handle.is_empty()
                || wallet::NonEmptyIdentifier::new(
                    snapshot.access_token_binding_handle.clone(),
                )
                .is_ok()) =>
        {
            Ok(())
        }
        Some(outbox)
            if outbox.delivery_state == wallet::OpenId4VciNotificationDeliveryState::Pending
                && outbox.delivery_attempts == 0
                && outbox.updated_at == updated_at
                && snapshot.notification_id == outbox.notification_id.as_str()
                && snapshot.access_token_binding_handle
                    == outbox.access_token_binding_handle.as_str()
                && snapshot.notification_endpoint == outbox.notification_endpoint.as_str() =>
        {
            let issuer = snapshot
                .credential_offer
                .as_option()
                .map(|offer| offer.credential_issuer.as_str())
                .ok_or(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))?;
            if issuer == outbox.credential_issuer.as_str() {
                Ok(())
            } else {
                Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit))
            }
        }
        None | Some(_) => Err(ConvertError::new(ConvertErrorReason::InvalidIssuanceCommit)),
    }
}
