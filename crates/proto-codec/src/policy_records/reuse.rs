// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded canonical reuse record conversion.

use super::codec::{
    decode, encode, invalid, nonzero, optional_digest, require, text, timestamp,
    POLICY_SCHEMA_VERSION,
};
use crate::convert::{credential_reuse_policy_from_proto, credential_reuse_policy_to_proto};
use crate::ProtoResult;
use buffa::MessageField;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types as wallet;
use zeroize::Zeroizing;

pub(super) fn reuse_instance_to_proto(v: &wallet::ReuseInstance) -> ProtoResult<pb::ReuseInstance> {
    require(v.valid_from < v.valid_until)?;
    let mut p = pb::ReuseInstance::default();
    p.credential_id = v.credential_id.as_str().to_owned();
    p.valid_from = v.valid_from.as_seconds();
    p.valid_until = v.valid_until.as_seconds();
    p.retired = v.retired;
    p.uses = v.uses;
    p.party_binding = v.party_binding.map_or_else(Vec::new, |d| d.to_vec());
    Ok(p)
}

pub(super) fn reuse_instance_from_proto(
    p: &pb::ReuseInstance,
) -> ProtoResult<wallet::ReuseInstance> {
    let from = timestamp(p.valid_from)?;
    let until = timestamp(p.valid_until)?;
    require(from < until)?;
    Ok(wallet::ReuseInstance {
        credential_id: wallet::CredentialRecordId::new(text(&p.credential_id)?)
            .map_err(|_| invalid())?,
        valid_from: from,
        valid_until: until,
        retired: p.retired,
        uses: p.uses,
        party_binding: optional_digest(&p.party_binding)?,
    })
}

pub(super) fn reuse_claim_to_proto(v: &wallet::ReuseClaim) -> pb::ReuseClaim {
    let mut p = pb::ReuseClaim::default();
    p.operation_id = v.operation_id.to_vec();
    p.request_digest = v.request_digest.to_vec();
    p.party_binding = v.party_binding.to_vec();
    p.credential_id = v.credential_id.as_str().to_owned();
    p.committed_at = v.committed_at.as_seconds();
    p
}

pub(super) fn reuse_claim_from_proto(p: &pb::ReuseClaim) -> ProtoResult<wallet::ReuseClaim> {
    Ok(wallet::ReuseClaim {
        operation_id: nonzero(&p.operation_id)?,
        request_digest: nonzero(&p.request_digest)?,
        party_binding: nonzero(&p.party_binding)?,
        credential_id: wallet::CredentialRecordId::new(text(&p.credential_id)?)
            .map_err(|_| invalid())?,
        committed_at: timestamp(p.committed_at)?,
    })
}

pub(super) fn replenishment_to_proto(v: &wallet::ReplenishmentIntent) -> pb::ReplenishmentIntent {
    let mut p = pb::ReplenishmentIntent::default();
    p.operation_id = v.operation_id.to_vec();
    p.requested_at = v.requested_at.as_seconds();
    p.fulfilled = v.fulfilled;
    p
}

pub(super) fn replenishment_from_proto(
    p: &pb::ReplenishmentIntent,
) -> ProtoResult<wallet::ReplenishmentIntent> {
    Ok(wallet::ReplenishmentIntent {
        operation_id: nonzero(&p.operation_id)?,
        requested_at: timestamp(p.requested_at)?,
        fulfilled: p.fulfilled,
    })
}

pub(super) fn reuse_to_proto(
    v: &wallet::CredentialReuseState,
) -> ProtoResult<pb::CredentialReuseState> {
    require(
        !v.instances.is_empty()
            && v.instances.len() <= wallet::MAX_REUSE_INSTANCES
            && v.claims.len() <= wallet::MAX_REUSE_CLAIMS,
    )?;
    let mut p = pb::CredentialReuseState::default();
    p.schema_version = POLICY_SCHEMA_VERSION;
    p.id = v.id.as_str().to_owned();
    p.policy = MessageField::some(credential_reuse_policy_to_proto(&v.policy));
    p.instances = v
        .instances
        .iter()
        .map(reuse_instance_to_proto)
        .collect::<ProtoResult<Vec<_>>>()?;
    p.next_index = v.next_index;
    p.claims = v.claims.iter().map(reuse_claim_to_proto).collect();
    p.replenishment = v.replenishment.as_ref().map(replenishment_to_proto).into();
    p.retired = v.retired;
    p.updated_at = v.updated_at.as_seconds();
    Ok(p)
}

pub(super) fn reuse_from_proto(
    p: &pb::CredentialReuseState,
) -> ProtoResult<wallet::CredentialReuseState> {
    require(
        p.schema_version == POLICY_SCHEMA_VERSION
            && !p.instances.is_empty()
            && p.instances.len() <= wallet::MAX_REUSE_INSTANCES
            && p.claims.len() <= wallet::MAX_REUSE_CLAIMS
            && usize::try_from(p.next_index).is_ok_and(|i| i < p.instances.len()),
    )?;
    Ok(wallet::CredentialReuseState {
        id: wallet::NonEmptyIdentifier::new(text(&p.id)?).map_err(|_| invalid())?,
        policy: credential_reuse_policy_from_proto(p.policy.as_option().ok_or_else(invalid)?)?,
        instances: p
            .instances
            .iter()
            .map(reuse_instance_from_proto)
            .collect::<ProtoResult<Vec<_>>>()?,
        next_index: p.next_index,
        claims: p
            .claims
            .iter()
            .map(reuse_claim_from_proto)
            .collect::<ProtoResult<Vec<_>>>()?,
        replenishment: p
            .replenishment
            .as_option()
            .map(replenishment_from_proto)
            .transpose()?,
        retired: p.retired,
        updated_at: timestamp(p.updated_at)?,
    })
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn encode_credential_reuse_state(
    value: &wallet::CredentialReuseState,
) -> ProtoResult<Zeroizing<Vec<u8>>> {
    let wire = reuse_to_proto(value)?;
    let _validated = reuse_from_proto(&wire)?;
    encode(&wire)
}

/// Encode or decode the bounded canonical Wallet persistence record.
pub fn decode_credential_reuse_state(bytes: &[u8]) -> ProtoResult<wallet::CredentialReuseState> {
    reuse_from_proto(&decode::<pb::CredentialReuseState>(bytes)?)
}
