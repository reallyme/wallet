// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate contact payload-kind extension labels.

use crate::{
    ContactPayloadKind, FlowError, FlowErrorReason, FlowResult, CONTACT_OTHER_KIND_MAX_BYTES,
};

/// Validate a contact payload kind before it crosses contact transport frames.
pub(crate) fn validate_contact_payload_kind(kind: &ContactPayloadKind) -> FlowResult<()> {
    if let ContactPayloadKind::Other(value) = kind {
        if value.is_empty() || value.len() > CONTACT_OTHER_KIND_MAX_BYTES {
            return Err(FlowError::new(FlowErrorReason::InvalidContactInput));
        }
    }

    Ok(())
}
