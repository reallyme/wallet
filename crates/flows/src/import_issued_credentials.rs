// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify issuer response envelopes before constructing inventory records.

use openid4vci_types::CredentialEnvelope;
use reallyme_wallet_inventory::import_validated_credential;
use reallyme_wallet_types::{
    CredentialRecord, CredentialRecordId, IssuerId, KeyHandleId, UnixTimestamp,
};
use std::collections::BTreeSet;

use crate::{FlowError, FlowErrorReason, FlowResult, IssuanceState, OpenId4VciIssuanceSession};

pub(crate) const MAX_ISSUED_CREDENTIALS_PER_RESPONSE: usize = 1_024;

/// Receipt-validation boundary implemented by the credential format layer.
///
/// Implementations verify the issuer signature, trust decision, validity,
/// envelope format, and holder-key binding before returning an encrypted local
/// record. Raw response envelopes are supplied by wallet-core so an adapter
/// cannot substitute unrelated credential bytes.
pub trait IssuedCredentialVerifier {
    /// Verify one response envelope and construct its encrypted inventory record.
    fn verify_issued_credential(
        &self,
        envelope: &CredentialEnvelope,
        expected_credential_issuer: &IssuerId,
        expected_holder_keys: &[KeyHandleId],
        received_at: UnixTimestamp,
    ) -> FlowResult<CredentialRecord>;
}

/// Verify and import a single credential response envelope.
pub fn import_openid4vci_issued_credential(
    session: OpenId4VciIssuanceSession,
    received_at: UnixTimestamp,
    verifier: &dyn IssuedCredentialVerifier,
) -> FlowResult<(OpenId4VciIssuanceSession, CredentialRecord)> {
    let (session, mut records) =
        import_openid4vci_issued_credentials(session, received_at, verifier)?;
    if records.len() != 1 {
        return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
    }
    let record = records
        .pop()
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidCredentialReceipt))?;
    Ok((session, record))
}

/// Verify every response envelope and return the records with a stored-state session.
///
/// This function performs no persistence. The host must commit the returned
/// records and session together through its atomic issuance storage boundary
/// before treating issuance as durably complete.
pub fn import_openid4vci_issued_credentials(
    session: OpenId4VciIssuanceSession,
    received_at: UnixTimestamp,
    verifier: &dyn IssuedCredentialVerifier,
) -> FlowResult<(OpenId4VciIssuanceSession, Vec<CredentialRecord>)> {
    let envelopes = credential_envelopes(&session)?;
    let holder_key_handle_ids = session.credential_binding_key_handle_ids.as_slice();
    if envelopes.len() > MAX_ISSUED_CREDENTIALS_PER_RESPONSE
        || envelopes.len() != holder_key_handle_ids.len()
    {
        return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
    }
    let expected_credential_issuer = IssuerId::new(session.credential_issuer.clone())
        .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReceipt))?;
    let expected_holder_keys = holder_key_handle_ids.iter().collect::<BTreeSet<_>>();
    if expected_holder_keys.len() != holder_key_handle_ids.len() {
        return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
    }

    let mut imported = Vec::with_capacity(envelopes.len());
    let mut credential_ids = Vec::with_capacity(envelopes.len());
    let mut unique_credential_ids = BTreeSet::new();
    let mut matched_holder_keys = BTreeSet::new();
    for envelope in envelopes {
        let record = verifier.verify_issued_credential(
            envelope,
            &expected_credential_issuer,
            holder_key_handle_ids,
            received_at,
        )?;
        // The Credential Issuer metadata identifier and the issuer identifier
        // authenticated from the credential are separate protocol values. The
        // format verifier owns the latter; this layer must only bind the record
        // to the metadata issuer from the accepted offer.
        let matched_holder_key = record
            .holder_key_handle_id
            .as_ref()
            .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidCredentialReceipt))?;
        if record.issuer_id != expected_credential_issuer
            || !expected_holder_keys.contains(matched_holder_key)
            || !matched_holder_keys.insert(matched_holder_key.clone())
            || record.received_at != received_at
        {
            return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
        }
        let record = import_validated_credential(record)
            .map_err(|_| FlowError::new(FlowErrorReason::InvalidCredentialReceipt))?;
        if !unique_credential_ids.insert(record.id.clone()) {
            return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
        }
        credential_ids.push(record.id.clone());
        imported.push(record);
    }
    if matched_holder_keys.len() != expected_holder_keys.len() {
        return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
    }
    let session = record_openid4vci_credentials_stored(session, credential_ids)?;
    Ok((session, imported))
}

/// Mark a non-empty, duplicate-free set of verified credentials as stored.
pub(crate) fn record_openid4vci_credentials_stored(
    mut session: OpenId4VciIssuanceSession,
    credential_ids: Vec<CredentialRecordId>,
) -> FlowResult<OpenId4VciIssuanceSession> {
    let unique = credential_ids.iter().cloned().collect::<BTreeSet<_>>();
    if credential_ids.is_empty() || unique.len() != credential_ids.len() {
        return Err(FlowError::new(FlowErrorReason::InvalidCredentialReceipt));
    }
    match session.state {
        IssuanceState::CredentialReceived => {
            session.state = IssuanceState::CredentialStored { credential_ids };
            Ok(session)
        }
        IssuanceState::OfferReceived
        | IssuanceState::ConsentCaptured
        | IssuanceState::Authorized
        | IssuanceState::TokenExchanged
        | IssuanceState::Deferred
        | IssuanceState::CredentialStored { .. } => {
            Err(FlowError::new(FlowErrorReason::InvalidTransition))
        }
    }
}

fn credential_envelopes(session: &OpenId4VciIssuanceSession) -> FlowResult<&[CredentialEnvelope]> {
    if session.state != IssuanceState::CredentialReceived {
        return Err(FlowError::new(FlowErrorReason::InvalidTransition));
    }
    session
        .credential_response
        .as_ref()
        .and_then(|response| response.credentials.as_deref())
        .filter(|credentials| !credentials.is_empty())
        .ok_or_else(|| FlowError::new(FlowErrorReason::InvalidTransition))
}
