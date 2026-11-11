// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate contact delivery message binding and lifetime.

use reallyme_wallet_types::UnixTimestamp;

use crate::contact_model::{
    CONTACT_CONTENT_TYPE_MAX_BYTES, CONTACT_MESSAGE_MAX_LIFETIME_SECONDS, CONTACT_SESSION_ID_LEN,
};
use crate::{
    validate_contact_kind::validate_contact_payload_kind, ContactLimits, ContactMessage,
    ContactProtocolVersion, FlowError, FlowErrorReason, FlowResult,
};

/// Validate a reassembled contact message before handing payload bytes upward.
///
/// A message may live at most one hour from `created_at` and its content type
/// at most 128 bytes, in addition to the configurable `ContactLimits`.
///
/// Frames carry no kind, transcript hash, or timestamps, so those fields of
/// `message` come from the host. The host must take them from the
/// authenticated session layer that delivered the frames, not from
/// unauthenticated input. The expected session identifier and transcript
/// hash must come from the session the Wallet established, so a message
/// reassembled for another session is refused.
pub fn validate_contact_message(
    message: &ContactMessage,
    expected_session_id: [u8; CONTACT_SESSION_ID_LEN],
    expected_session_transcript_sha256: [u8; 32],
    now: UnixTimestamp,
    limits: ContactLimits,
) -> FlowResult<()> {
    if limits.max_message_bytes == 0 {
        return Err(FlowError::new(FlowErrorReason::InvalidContactLimits));
    }
    let lifetime = message
        .expires_at
        .as_seconds()
        .checked_sub(message.created_at.as_seconds());
    if message.version != ContactProtocolVersion::V1
        || message.created_at > now
        || !lifetime
            .is_some_and(|seconds| (1..=CONTACT_MESSAGE_MAX_LIFETIME_SECONDS).contains(&seconds))
        || message.content_type.as_deref().is_some_and(|content_type| {
            content_type.is_empty()
                || content_type.len() > CONTACT_CONTENT_TYPE_MAX_BYTES
                || !content_type
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        })
    {
        return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
    }
    validate_contact_payload_kind(&message.kind)?;
    if message.payload.len() > limits.max_message_bytes {
        return Err(FlowError::new(FlowErrorReason::ContactMessageTooLarge));
    }
    if message.session_id != expected_session_id
        || message.session_transcript_sha256 != expected_session_transcript_sha256
    {
        return Err(FlowError::new(
            FlowErrorReason::ContactSessionTranscriptMismatch,
        ));
    }
    if now >= message.expires_at {
        return Err(FlowError::new(FlowErrorReason::ContactMessageExpired));
    }

    Ok(())
}
