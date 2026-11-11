// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded canonical execution record conversion.

use super::codec::{
    decode, encode, flow_disposition_from_proto, flow_disposition_to_proto,
    flow_effect_kind_from_proto, flow_effect_kind_to_proto, flow_effect_state_from_proto,
    flow_effect_state_to_proto, invalid, nonzero, require, text, timestamp, POLICY_SCHEMA_VERSION,
};
use crate::convert::{flow_kind_from_proto, flow_kind_to_proto};
use crate::ProtoResult;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

pub(super) fn effect_to_proto(v: &wallet::FlowEffect) -> pb::FlowEffect {
    let mut p = pb::FlowEffect::default();
    p.request_bytes = v.request_bytes.clone();
    p.id = v.id.to_vec();
    p.request_digest = v.request_digest.to_vec();
    p.kind = flow_effect_kind_to_proto(v.kind);
    p.state = flow_effect_state_to_proto(v.state);
    p
}

pub(super) fn effect_from_proto(p: &pb::FlowEffect) -> ProtoResult<wallet::FlowEffect> {
    require(!p.request_bytes.is_empty() && p.request_bytes.len() <= wallet::MAX_FLOW_EFFECT_BYTES)?;
    Ok(wallet::FlowEffect {
        request_bytes: p.request_bytes.clone(),
        id: nonzero(&p.id)?,
        request_digest: nonzero(&p.request_digest)?,
        kind: flow_effect_kind_from_proto(p.kind)?,
        state: flow_effect_state_from_proto(p.state)?,
    })
}

pub(super) fn execution_to_proto(
    v: &wallet::FlowExecutionRecord,
) -> ProtoResult<pb::FlowExecutionRecord> {
    require(
        v.effects.len() <= wallet::MAX_FLOW_EFFECTS
            && !v.snapshot.is_empty()
            && v.snapshot.len() <= wallet::MAX_EXECUTION_SNAPSHOT_BYTES,
    )?;
    let total = v
        .effects
        .iter()
        .try_fold(0_usize, |total, effect| {
            if effect.request_bytes.is_empty()
                || effect.request_bytes.len() > wallet::MAX_FLOW_EFFECT_BYTES
            {
                return None;
            }
            total.checked_add(effect.request_bytes.len())
        })
        .ok_or_else(invalid)?;
    require(total <= wallet::MAX_FLOW_EFFECT_TOTAL_BYTES)?;
    let mut p = pb::FlowExecutionRecord::default();
    p.schema_version = POLICY_SCHEMA_VERSION;
    p.id = v.id.as_str().to_owned();
    p.kind = flow_kind_to_proto(v.kind).into();
    p.intent_digest = v.intent_digest.to_vec();
    p.disposition = flow_disposition_to_proto(v.disposition);
    p.effects = v.effects.iter().map(effect_to_proto).collect();
    p.snapshot = v.snapshot.clone();
    p.expires_at = v.expires_at.as_seconds();
    p.updated_at = v.updated_at.as_seconds();
    Ok(p)
}

pub(super) fn execution_from_proto(
    p: &pb::FlowExecutionRecord,
) -> ProtoResult<wallet::FlowExecutionRecord> {
    require(
        p.schema_version == POLICY_SCHEMA_VERSION
            && p.effects.len() <= wallet::MAX_FLOW_EFFECTS
            && !p.snapshot.is_empty()
            && p.snapshot.len() <= wallet::MAX_EXECUTION_SNAPSHOT_BYTES,
    )?;
    let total = p
        .effects
        .iter()
        .try_fold(0_usize, |total, effect| {
            if effect.request_bytes.is_empty()
                || effect.request_bytes.len() > wallet::MAX_FLOW_EFFECT_BYTES
            {
                return None;
            }
            total.checked_add(effect.request_bytes.len())
        })
        .ok_or_else(invalid)?;
    require(total <= wallet::MAX_FLOW_EFFECT_TOTAL_BYTES)?;
    Ok(wallet::FlowExecutionRecord {
        id: wallet::FlowSnapshotId::new(text(&p.id)?).map_err(|_| invalid())?,
        kind: flow_kind_from_proto(p.kind.as_known().ok_or_else(invalid)?)?,
        intent_digest: nonzero(&p.intent_digest)?,
        disposition: flow_disposition_from_proto(p.disposition)?,
        effects: p
            .effects
            .iter()
            .map(effect_from_proto)
            .collect::<ProtoResult<Vec<_>>>()?,
        snapshot: p.snapshot.clone(),
        expires_at: timestamp(p.expires_at)?,
        updated_at: timestamp(p.updated_at)?,
    })
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn encode_flow_execution_record(
    value: &wallet::FlowExecutionRecord,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let wire = execution_to_proto(value)?;
    let _validated = execution_from_proto(&wire)?;
    encode(&wire)
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn decode_flow_execution_record(bytes: &[u8]) -> ProtoResult<wallet::FlowExecutionRecord> {
    execution_from_proto(&decode::<pb::FlowExecutionRecord>(bytes)?)
}
