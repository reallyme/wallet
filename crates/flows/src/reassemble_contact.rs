// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reassemble bounded contact delivery frames.

use crate::{
    ContactFrame, ContactLimits, ContactProtocolVersion, FlowError, FlowErrorReason, FlowResult,
};
use zeroize::Zeroizing;

/// Reassemble contact frames into the original payload bytes.
pub fn reassemble_contact_frames(
    frames: &[ContactFrame],
    limits: ContactLimits,
) -> FlowResult<Zeroizing<Vec<u8>>> {
    validate_reassembly_limits(limits)?;
    if frames.is_empty() {
        return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
    }
    if frames.len() > limits.max_frames {
        return Err(FlowError::new(FlowErrorReason::ContactTooManyFrames));
    }

    let first = &frames[0];
    if first.version != ContactProtocolVersion::V1 {
        return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
    }
    let total = usize::from(first.total);
    if total == 0 || total > limits.max_frames || total != frames.len() {
        return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
    }

    for frame in frames {
        if frame.version != ContactProtocolVersion::V1
            || frame.session_id != first.session_id
            || frame.message_id != first.message_id
            || frame.total != first.total
        {
            return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
        }
        if frame.chunk.len() > limits.max_frame_payload_bytes {
            return Err(FlowError::new(FlowErrorReason::ContactFrameTooLarge));
        }
    }

    // Sort references rather than copying privacy-bearing frame buffers.
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(frames.len())
        .map_err(|_| FlowError::new(FlowErrorReason::ContactAllocationFailed))?;
    sorted.extend(frames.iter());
    sorted.sort_by_key(|frame| frame.sequence);
    for (index, frame) in sorted.iter().enumerate() {
        if usize::from(frame.sequence) != index {
            return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
        }
    }

    // Reserve once before copying any privacy-bearing bytes. Growing a Vec after
    // copying a frame could release an earlier allocation without wiping it.
    let mut total_len = 0_usize;
    for frame in &sorted {
        total_len = total_len
            .checked_add(frame.chunk.len())
            .ok_or(FlowError::new(FlowErrorReason::ContactMessageTooLarge))?;
        if total_len > limits.max_message_bytes {
            return Err(FlowError::new(FlowErrorReason::ContactMessageTooLarge));
        }
    }

    let mut payload = Zeroizing::new(Vec::new());
    payload
        .try_reserve_exact(total_len)
        .map_err(|_| FlowError::new(FlowErrorReason::ContactAllocationFailed))?;
    for frame in sorted {
        payload.extend_from_slice(&frame.chunk);
    }

    Ok(payload)
}

fn validate_reassembly_limits(limits: ContactLimits) -> FlowResult<()> {
    if limits.max_message_bytes == 0
        || limits.max_frame_payload_bytes == 0
        || limits.max_frames == 0
    {
        return Err(FlowError::new(FlowErrorReason::InvalidContactLimits));
    }

    Ok(())
}
