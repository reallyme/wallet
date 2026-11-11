// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded canonical history record conversion.

use super::codec::{
    decode, encode, fixed, history_failure_reason_from_proto, history_failure_reason_to_proto,
    history_outcome_from_proto, history_outcome_to_proto, history_purpose_from_proto,
    history_purpose_to_proto, invalid, nonzero, optional_digest, require, text, timestamp,
    HISTORY_SCHEMA_VERSION,
};
use crate::ProtoResult;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

pub(super) fn history_to_proto(
    v: &wallet::TransactionHistoryRecord,
) -> ProtoResult<pb::TransactionHistoryRecord> {
    require(
        v.requested.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && v.presented.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && v.credential_ids.len() <= wallet::MAX_HISTORY_CREDENTIALS,
    )?;
    let mut p = pb::TransactionHistoryRecord::default();
    p.schema_version = HISTORY_SCHEMA_VERSION;
    p.id = v.id.as_str().to_owned();
    p.purpose = history_purpose_to_proto(v.purpose);
    p.outcome = history_outcome_to_proto(v.outcome);
    p.reason = history_failure_reason_to_proto(v.reason);
    p.relying_party_id = v
        .relying_party_id
        .as_ref()
        .map_or_else(String::new, |id| id.as_str().to_owned());
    p.requested = v.requested.iter().map(|n| n.as_str().to_owned()).collect();
    p.presented = v.presented.iter().map(|n| n.as_str().to_owned()).collect();
    p.credential_ids = v
        .credential_ids
        .iter()
        .map(|n| n.as_str().to_owned())
        .collect();
    p.consent_digest = v.consent_digest.map_or_else(Vec::new, |d| d.to_vec());
    p.operation_id = v.operation_id.as_str().to_owned();
    p.occurred_at = v.occurred_at.as_seconds();
    p.sequence = v.sequence;
    p.previous_hash = v.previous_hash.to_vec();
    p.entry_hash = v.entry_hash.to_vec();
    Ok(p)
}

pub(super) fn history_from_proto(
    p: &pb::TransactionHistoryRecord,
) -> ProtoResult<wallet::TransactionHistoryRecord> {
    require(
        p.schema_version == HISTORY_SCHEMA_VERSION
            && p.requested.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && p.presented.len() <= wallet::MAX_HISTORY_ATTRIBUTES
            && p.credential_ids.len() <= wallet::MAX_HISTORY_CREDENTIALS,
    )?;
    Ok(wallet::TransactionHistoryRecord {
        id: wallet::TransactionLogEntryId::new(text(&p.id)?).map_err(|_| invalid())?,
        purpose: history_purpose_from_proto(p.purpose)?,
        outcome: history_outcome_from_proto(p.outcome)?,
        reason: history_failure_reason_from_proto(p.reason)?,
        relying_party_id: if p.relying_party_id.is_empty() {
            None
        } else {
            Some(wallet::RelyingPartyId::new(text(&p.relying_party_id)?).map_err(|_| invalid())?)
        },
        requested: p
            .requested
            .iter()
            .map(|n| wallet::AttributeName::new(text(n)?).map_err(|_| invalid()))
            .collect::<ProtoResult<Vec<_>>>()?,
        presented: p
            .presented
            .iter()
            .map(|n| wallet::AttributeName::new(text(n)?).map_err(|_| invalid()))
            .collect::<ProtoResult<Vec<_>>>()?,
        credential_ids: p
            .credential_ids
            .iter()
            .map(|n| wallet::CredentialRecordId::new(text(n)?).map_err(|_| invalid()))
            .collect::<ProtoResult<Vec<_>>>()?,
        consent_digest: optional_digest(&p.consent_digest)?,
        operation_id: wallet::NonEmptyIdentifier::new(text(&p.operation_id)?)
            .map_err(|_| invalid())?,
        occurred_at: timestamp(p.occurred_at)?,
        sequence: p.sequence,
        previous_hash: fixed(&p.previous_hash)?,
        entry_hash: nonzero(&p.entry_hash)?,
    })
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn encode_transaction_history_record(
    value: &wallet::TransactionHistoryRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let wire = history_to_proto(value)?;
    let _validated = history_from_proto(&wire)?;
    encode(&wire)
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn decode_transaction_history_record(
    bytes: &[u8],
) -> ProtoResult<wallet::TransactionHistoryRecord> {
    history_from_proto(&decode::<pb::TransactionHistoryRecord>(bytes)?)
}
