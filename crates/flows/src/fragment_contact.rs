// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fragment contact delivery messages into bounded frames.

use crate::{
    validate_contact_kind::validate_contact_payload_kind, ContactFrame, ContactLimits,
    ContactMessage, ContactProtocolVersion, FlowError, FlowErrorReason, FlowResult,
};

/// Fragment a contact message into transport-neutral frames.
pub fn fragment_contact_message(
    message: &ContactMessage,
    limits: ContactLimits,
) -> FlowResult<Vec<ContactFrame>> {
    validate_fragment_limits(limits)?;
    if message.version != ContactProtocolVersion::V1 {
        return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
    }
    validate_contact_payload_kind(&message.kind)?;
    if message.payload.len() > limits.max_message_bytes {
        return Err(FlowError::new(FlowErrorReason::ContactMessageTooLarge));
    }

    let total = message
        .payload
        .len()
        .div_ceil(limits.max_frame_payload_bytes)
        .max(1);
    if total > limits.max_frames || total > usize::from(u16::MAX) {
        return Err(FlowError::new(FlowErrorReason::ContactTooManyFrames));
    }
    let total_u16 =
        u16::try_from(total).map_err(|_| FlowError::new(FlowErrorReason::ContactTooManyFrames))?;

    if message.payload.is_empty() {
        return Ok(vec![ContactFrame {
            version: ContactProtocolVersion::V1,
            session_id: message.session_id,
            message_id: message.message_id,
            sequence: 0,
            total: 1,
            chunk: Vec::new(),
        }]);
    }

    let mut frames = Vec::with_capacity(total);
    for (index, chunk) in message
        .payload
        .chunks(limits.max_frame_payload_bytes)
        .enumerate()
    {
        let sequence = u16::try_from(index)
            .map_err(|_| FlowError::new(FlowErrorReason::ContactTooManyFrames))?;
        frames.push(ContactFrame {
            version: ContactProtocolVersion::V1,
            session_id: message.session_id,
            message_id: message.message_id,
            sequence,
            total: total_u16,
            chunk: chunk.to_vec(),
        });
    }

    Ok(frames)
}

fn validate_fragment_limits(limits: ContactLimits) -> FlowResult<()> {
    if limits.max_message_bytes == 0
        || limits.max_frame_payload_bytes == 0
        || limits.max_frames == 0
        || limits.max_frame_payload_bytes > limits.max_message_bytes
    {
        return Err(FlowError::new(FlowErrorReason::InvalidContactLimits));
    }

    Ok(())
}
