// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    decode_consent_receipt, decode_credential_reuse_state, decode_flow_execution_record,
    decode_transaction_history_record, encode_flow_execution_record,
};
use crate::{ProtoError, MAX_WALLET_PROTO_MESSAGE_BYTES};
use buffa::Message;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_types::{
    FlowDisposition, FlowExecutionRecord, FlowKind, FlowSnapshotId, UnixTimestamp, WalletTypesError,
};
use thiserror::Error;
#[test]
fn execution_round_trip_and_rejects_schema_enum_duplicate_unknown_and_truncation(
) -> Result<(), TestError> {
    let state = FlowExecutionRecord {
        id: FlowSnapshotId::new("flow".into())?,
        kind: FlowKind::Presentation,
        intent_digest: [1; 32],
        disposition: FlowDisposition::Active,
        effects: vec![],
        snapshot: vec![1, 2],
        expires_at: UnixTimestamp::from_seconds(100)?,
        updated_at: UnixTimestamp::from_seconds(20)?,
    };
    let bytes = encode_flow_execution_record(&state)?;
    assert!(decode_flow_execution_record(&bytes)? == state);
    for length in 0..bytes.len() {
        assert!(decode_flow_execution_record(&bytes[..length]).is_err());
    }
    let mut unknown = bytes.to_vec();
    unknown.extend_from_slice(&[0xf8, 0x07, 0x01]);
    assert!(decode_flow_execution_record(&unknown).is_err());
    let mut duplicate = bytes.to_vec();
    duplicate.extend_from_slice(&[8, 1]);
    assert!(decode_flow_execution_record(&duplicate).is_err());
    let mut wire =
        pb::FlowExecutionRecord::decode_from_slice(&bytes).map_err(|_| TestError::Decode)?;
    wire.schema_version = 9;
    assert!(decode_flow_execution_record(&wire.encode_to_vec()).is_err());
    wire.schema_version = 1;
    wire.disposition = 999.into();
    assert!(decode_flow_execution_record(&wire.encode_to_vec()).is_err());
    Ok(())
}
#[test]
fn empty_malformed_and_oversized_inputs_fail_all_policy_decoders() {
    let oversized = vec![0; MAX_WALLET_PROTO_MESSAGE_BYTES + 1];
    for bytes in [&[][..], &[0xff][..], oversized.as_slice()] {
        assert!(decode_credential_reuse_state(bytes).is_err());
        assert!(decode_consent_receipt(bytes).is_err());
        assert!(decode_transaction_history_record(bytes).is_err());
        assert!(decode_flow_execution_record(bytes).is_err());
    }
}
#[derive(Debug, Error)]
enum TestError {
    #[error("types")]
    Types(#[from] WalletTypesError),
    #[error("proto")]
    Proto(#[from] ProtoError),
    #[error("decode")]
    Decode,
}

#[test]
fn reuse_receipt_and_history_records_round_trip_with_exact_metadata() -> Result<(), TestError> {
    use reallyme_wallet_types::{
        AttributeName, ConsentAction, ConsentActionKind, ConsentCapture, ConsentDecision,
        ConsentPolicyChoice, ConsentPolicyContext, ConsentReceipt, ConsentRetention, ConsentScope,
        CredentialRecordId, CredentialReuseMethod, CredentialReusePolicySelection,
        CredentialReuseState, DisclosurePolicyDecision, HistoryFailureReason, HistoryOutcome,
        HistoryPurpose, NonEmptyIdentifier, ReaderSessionBinding, RelyingPartyId, ReuseInstance,
        TransactionHistoryRecord, TransactionLogEntryId,
    };
    let t = |n| UnixTimestamp::from_seconds(n);
    let state = CredentialReuseState {
        id: NonEmptyIdentifier::new("cohort".into())?,
        policy: CredentialReusePolicySelection::new(
            NonEmptyIdentifier::new("pid".into())?,
            CredentialReuseMethod::OnceOnly,
            Some(2),
            Some(1),
            None,
        )?,
        instances: vec![
            ReuseInstance {
                credential_id: CredentialRecordId::new("a".into())?,
                valid_from: t(10)?,
                valid_until: t(100)?,
                retired: false,
                uses: 0,
                party_binding: None,
            },
            ReuseInstance {
                credential_id: CredentialRecordId::new("b".into())?,
                valid_from: t(10)?,
                valid_until: t(100)?,
                retired: false,
                uses: 0,
                party_binding: None,
            },
        ],
        next_index: 0,
        claims: vec![],
        replenishment: None,
        retired: false,
        updated_at: t(20)?,
    };
    let bytes = super::encode_credential_reuse_state(&state)?;
    assert!(super::decode_credential_reuse_state(&bytes)? == state);
    let scope = ConsentScope {
        attributes: vec![AttributeName::new("age".into())?],
    };
    let rp = RelyingPartyId::new("https://reader.example".into())?;
    let receipt = ConsentReceipt {
        capture: ConsentCapture {
            relying_party_id: rp.clone(),
            requested_scope: scope.clone(),
            selected_action: ConsentAction {
                kind: ConsentActionKind::Disclose,
                scope,
                derivation_id: None,
                derivation_inputs: vec![],
            },
            request_nonce: NonEmptyIdentifier::new("nonce".into())?,
            request_digest: [4; 32],
            policy_decision: DisclosurePolicyDecision::Allowed,
            user_decision: ConsentDecision::Approved,
            captured_at: t(20)?,
        },
        policy: Some(ConsentPolicyContext {
            purpose: NonEmptyIdentifier::new("age-check".into())?,
            retention: ConsentRetention::Until(t(80)?),
            policies: vec![ConsentPolicyChoice {
                id: NonEmptyIdentifier::new("terms".into())?,
                version: NonEmptyIdentifier::new("1".into())?,
                document_digest: [5; 32],
                mandatory: true,
                accepted: true,
            }],
            transaction_digest: [6; 32],
        }),
        reader: Some(ReaderSessionBinding {
            reader_id: rp.clone(),
            certificate_digest: [1; 32],
            session_digest: [2; 32],
            request_digest: [3; 32],
            authenticated_at: t(10)?,
            valid_until: t(100)?,
        }),
    };
    let bytes = super::encode_consent_receipt(&receipt)?;
    assert!(super::decode_consent_receipt(&bytes)? == receipt);
    let history = TransactionHistoryRecord {
        id: TransactionLogEntryId::new("history".into())?,
        purpose: HistoryPurpose::Presentation,
        outcome: HistoryOutcome::Completed,
        reason: HistoryFailureReason::None,
        relying_party_id: Some(rp),
        requested: vec![AttributeName::new("age".into())?],
        presented: vec![AttributeName::new("age".into())?],
        credential_ids: vec![CredentialRecordId::new("a".into())?],
        consent_digest: Some([4; 32]),
        operation_id: NonEmptyIdentifier::new("op".into())?,
        occurred_at: t(20)?,
        sequence: 1,
        previous_hash: [0; 32],
        entry_hash: [8; 32],
    };
    let bytes = super::encode_transaction_history_record(&history)?;
    assert!(super::decode_transaction_history_record(&bytes)? == history);
    Ok(())
}

#[test]
fn maximum_execution_payload_is_bounded_and_round_trips() -> Result<(), TestError> {
    use reallyme_wallet_types::{
        FlowEffect, FlowEffectKind, FlowEffectState, MAX_FLOW_EFFECT_BYTES,
        MAX_FLOW_EFFECT_TOTAL_BYTES,
    };
    let payload = vec![7; MAX_FLOW_EFFECT_BYTES];
    let digest = crypto_sha2_256::digest(&payload).into_bytes();
    let effects = vec![
        FlowEffect {
            id: [1; 32],
            request_bytes: payload.clone(),
            request_digest: digest,
            kind: FlowEffectKind::Signing,
            state: FlowEffectState::Confirmed,
        },
        FlowEffect {
            id: [2; 32],
            request_bytes: payload,
            request_digest: digest,
            kind: FlowEffectKind::Signing,
            state: FlowEffectState::Confirmed,
        },
    ];
    assert_eq!(
        effects.iter().map(|e| e.request_bytes.len()).sum::<usize>(),
        MAX_FLOW_EFFECT_TOTAL_BYTES
    );
    let state = FlowExecutionRecord {
        id: FlowSnapshotId::new("large-flow".into())?,
        kind: FlowKind::Presentation,
        intent_digest: [1; 32],
        disposition: FlowDisposition::Active,
        effects,
        snapshot: vec![1; reallyme_wallet_types::MAX_EXECUTION_SNAPSHOT_BYTES],
        expires_at: UnixTimestamp::from_seconds(100)?,
        updated_at: UnixTimestamp::from_seconds(20)?,
    };
    let bytes = encode_flow_execution_record(&state)?;
    assert!(decode_flow_execution_record(&bytes)? == state);
    let oversized = vec![
        0;
        super::MAX_POLICY_RECORD_BYTES
            .checked_add(1)
            .ok_or(TestError::Decode)?
    ];
    assert_eq!(
        decode_flow_execution_record(&oversized)
            .err()
            .map(|e| e.reason),
        Some(crate::ProtoErrorReason::MessageTooLarge)
    );
    Ok(())
}
