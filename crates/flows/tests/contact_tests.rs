// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for contact delivery fragmentation, reassembly, and validation.

use reallyme_wallet_flows::{
    fragment_contact_message, reassemble_contact_frames, validate_contact_message, ContactFrame,
    ContactLimits, ContactMessage, ContactMessageParts, ContactPayloadKind, ContactProtocolVersion,
    FlowError, FlowErrorReason, CONTACT_OTHER_KIND_MAX_BYTES, CONTACT_SESSION_ID_LEN,
    CONTACT_TRANSCRIPT_HASH_LEN,
};
use reallyme_wallet_types::{UnixTimestamp, WalletTypesError};

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn session_id() -> [u8; CONTACT_SESSION_ID_LEN] {
    [7_u8; CONTACT_SESSION_ID_LEN]
}

fn transcript_hash() -> [u8; CONTACT_TRANSCRIPT_HASH_LEN] {
    [8_u8; CONTACT_TRANSCRIPT_HASH_LEN]
}

fn limits() -> ContactLimits {
    ContactLimits {
        max_message_bytes: 64,
        max_frame_payload_bytes: 5,
        max_frames: 16,
    }
}

fn message(payload: Vec<u8>) -> Result<ContactMessage, WalletTypesError> {
    Ok(ContactMessage::from_parts(ContactMessageParts {
        kind: ContactPayloadKind::Request,
        session_id: session_id(),
        session_transcript_sha256: transcript_hash(),
        message_id: 42,
        content_type: Some("application/cbor".to_owned()),
        created_at: timestamp(10)?,
        expires_at: timestamp(20)?,
        payload,
    }))
}

#[test]
fn contact_fragmentation_round_trips_payload() -> Result<(), TestError> {
    let msg = message(b"hello contact channel".to_vec())?;
    let frames = fragment_contact_message(&msg, limits())?;

    assert_eq!(frames.len(), 5);
    let payload = reassemble_contact_frames(&frames, limits())?;

    assert_eq!(payload.as_slice(), msg.payload.as_slice());
    Ok(())
}

#[test]
fn contact_reassembly_accepts_out_of_order_frames() -> Result<(), TestError> {
    let msg = message(b"abcdefghi".to_vec())?;
    let mut frames = fragment_contact_message(&msg, limits())?;
    frames.reverse();

    let payload = reassemble_contact_frames(&frames, limits())?;

    assert_eq!(payload.as_slice(), msg.payload.as_slice());
    Ok(())
}

#[test]
fn contact_reassembly_rejects_duplicate_sequence() -> Result<(), TestError> {
    let msg = message(b"abcdefghi".to_vec())?;
    let mut frames = fragment_contact_message(&msg, limits())?;
    frames[1].sequence = frames[0].sequence;

    let result = reassemble_contact_frames(&frames, limits());

    assert_reason(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_reassembly_rejects_missing_frame() -> Result<(), TestError> {
    let msg = message(b"abcdefghi".to_vec())?;
    let mut frames = fragment_contact_message(&msg, limits())?;
    let _removed = frames.remove(1);

    let result = reassemble_contact_frames(&frames, limits());

    assert_reason(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_reassembly_rejects_mismatched_session() -> Result<(), TestError> {
    let msg = message(b"abcdefghi".to_vec())?;
    let mut frames = fragment_contact_message(&msg, limits())?;
    frames[1].session_id = [9_u8; CONTACT_SESSION_ID_LEN];

    let result = reassemble_contact_frames(&frames, limits());

    assert_reason(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_reassembly_rejects_mismatched_message_id() -> Result<(), TestError> {
    let msg = message(b"abcdefghi".to_vec())?;
    let mut frames = fragment_contact_message(&msg, limits())?;
    frames[1].message_id = 43;

    let result = reassemble_contact_frames(&frames, limits());

    assert_reason(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_reassembly_rejects_oversized_frame_chunk() -> Result<(), TestError> {
    let frame = ContactFrame {
        version: ContactProtocolVersion::V1,
        session_id: session_id(),
        message_id: 42,
        sequence: 0,
        total: 1,
        chunk: vec![0_u8; 6],
    };

    let result = reassemble_contact_frames(&[frame], limits());

    assert_reason(result, FlowErrorReason::ContactFrameTooLarge);
    Ok(())
}

#[test]
fn contact_reassembly_rejects_aggregate_over_limit() -> Result<(), TestError> {
    let msg = message(vec![0xA5_u8; 65])?;
    let relaxed = ContactLimits {
        max_message_bytes: 65,
        max_frame_payload_bytes: 5,
        max_frames: 16,
    };
    let frames = fragment_contact_message(&msg, relaxed)?;

    let result = reassemble_contact_frames(&frames, limits());

    assert_reason(result, FlowErrorReason::ContactMessageTooLarge);
    Ok(())
}

#[test]
fn contact_protocol_version_has_stable_wire_value() {
    assert_eq!(ContactProtocolVersion::V1.wire_value(), "1.0");
}

#[test]
fn contact_fragmentation_rejects_oversized_message() -> Result<(), TestError> {
    let msg = message(vec![0_u8; 65])?;

    let result = fragment_contact_message(&msg, limits());

    assert_reason(result, FlowErrorReason::ContactMessageTooLarge);
    Ok(())
}

#[test]
fn contact_fragmentation_rejects_too_many_frames() -> Result<(), TestError> {
    let msg = message(vec![0_u8; 11])?;
    let constrained = ContactLimits {
        max_message_bytes: 64,
        max_frame_payload_bytes: 5,
        max_frames: 2,
    };

    let result = fragment_contact_message(&msg, constrained);

    assert_reason(result, FlowErrorReason::ContactTooManyFrames);
    Ok(())
}

#[test]
fn contact_fragmentation_preserves_future_payload_kind() -> Result<(), TestError> {
    let mut msg = message(b"payload".to_vec())?;
    msg.kind = ContactPayloadKind::Other("proximity_preview".to_owned());

    let frames = fragment_contact_message(&msg, limits())?;

    assert_eq!(frames.len(), 2);
    assert_eq!(
        msg.kind,
        ContactPayloadKind::Other("proximity_preview".to_owned())
    );
    Ok(())
}

#[test]
fn contact_fragmentation_rejects_empty_future_payload_kind() -> Result<(), TestError> {
    let mut msg = message(b"payload".to_vec())?;
    msg.kind = ContactPayloadKind::Other(String::new());

    let result = fragment_contact_message(&msg, limits());

    assert_reason(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_validation_rejects_oversized_future_payload_kind() -> Result<(), TestError> {
    let mut msg = message(b"payload".to_vec())?;
    msg.kind = ContactPayloadKind::Other("x".repeat(CONTACT_OTHER_KIND_MAX_BYTES + 1));

    let result = validate_contact_message(
        &msg,
        session_id(),
        transcript_hash(),
        timestamp(15)?,
        limits(),
    );

    assert_reason_unit(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_validation_accepts_bound_message() -> Result<(), TestError> {
    let msg = message(b"payload".to_vec())?;

    let result = validate_contact_message(
        &msg,
        session_id(),
        transcript_hash(),
        timestamp(15)?,
        limits(),
    );

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn contact_validation_rejects_transcript_mismatch() -> Result<(), TestError> {
    let msg = message(b"payload".to_vec())?;

    let result = validate_contact_message(
        &msg,
        session_id(),
        [9_u8; CONTACT_TRANSCRIPT_HASH_LEN],
        timestamp(15)?,
        limits(),
    );

    assert_reason_unit(result, FlowErrorReason::ContactSessionTranscriptMismatch);
    Ok(())
}

#[test]
fn contact_validation_rejects_a_message_for_another_session() -> Result<(), TestError> {
    let msg = message(b"payload".to_vec())?;

    let result = validate_contact_message(
        &msg,
        [9_u8; CONTACT_SESSION_ID_LEN],
        transcript_hash(),
        timestamp(15)?,
        limits(),
    );

    assert_reason_unit(result, FlowErrorReason::ContactSessionTranscriptMismatch);
    Ok(())
}

#[test]
fn contact_validation_rejects_expired_message() -> Result<(), TestError> {
    let msg = message(b"payload".to_vec())?;

    let result = validate_contact_message(
        &msg,
        session_id(),
        transcript_hash(),
        timestamp(21)?,
        limits(),
    );

    assert_reason_unit(result, FlowErrorReason::ContactMessageExpired);
    Ok(())
}

#[test]
fn contact_validation_rejects_future_created_message() -> Result<(), TestError> {
    let msg = message(b"payload".to_vec())?;

    let result = validate_contact_message(
        &msg,
        session_id(),
        transcript_hash(),
        timestamp(9)?,
        limits(),
    );

    assert_reason_unit(result, FlowErrorReason::InvalidContactInput);
    Ok(())
}

#[test]
fn contact_validation_rejects_unbounded_or_inverted_lifetime() -> Result<(), TestError> {
    for (created_at, expires_at) in [(10, 10), (10, 9), (10, 10 + 3_601)] {
        let mut msg = message(b"payload".to_vec())?;
        msg.created_at = timestamp(created_at)?;
        msg.expires_at = timestamp(expires_at)?;
        let result = validate_contact_message(
            &msg,
            session_id(),
            transcript_hash(),
            timestamp(10)?,
            limits(),
        );
        assert_reason_unit(result, FlowErrorReason::InvalidContactInput);
    }
    Ok(())
}

#[test]
fn contact_validation_rejects_malformed_content_type() -> Result<(), TestError> {
    for content_type in [String::new(), "x".repeat(129), "text/plain\n".to_owned()] {
        let mut msg = message(b"payload".to_vec())?;
        msg.content_type = Some(content_type);
        let result = validate_contact_message(
            &msg,
            session_id(),
            transcript_hash(),
            timestamp(15)?,
            limits(),
        );
        assert_reason_unit(result, FlowErrorReason::InvalidContactInput);
    }
    Ok(())
}

#[test]
fn contact_validation_treats_expiry_as_exclusive() -> Result<(), TestError> {
    let msg = message(b"payload".to_vec())?;
    let result = validate_contact_message(
        &msg,
        session_id(),
        transcript_hash(),
        timestamp(20)?,
        limits(),
    );
    assert_reason_unit(result, FlowErrorReason::ContactMessageExpired);
    Ok(())
}

fn assert_reason<T>(result: Result<T, FlowError>, reason: FlowErrorReason) {
    assert!(matches!(result, Err(error) if error.reason == reason));
}

fn assert_reason_unit(result: Result<(), FlowError>, reason: FlowErrorReason) {
    assert!(matches!(result, Err(error) if error.reason == reason));
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("flow")]
    Flow(#[from] FlowError),
    #[error("wallet_types")]
    WalletTypes(#[from] WalletTypesError),
}
