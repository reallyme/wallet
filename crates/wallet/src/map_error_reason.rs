// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Map wallet-owned Rust error reasons to the generated public protobuf enum.
//!
//! The member crates keep detailed, strongly typed internal reasons for local
//! control flow. This facade provides the stable category mapping used by
//! runtime adapters, downstream SDK composition, conformance, and audit
//! surfaces.

use buffa::{EnumValue, Enumeration, MessageField};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    self as pb, WalletErrorReason,
};
use reallyme_wallet_proto_codec::convert::ConvertErrorReason;

const WALLET_DOMAIN: IdentityStackErrorDomain =
    IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_WALLET;

fn wallet_error(reason: WalletErrorReason, detail: pb::wallet_error::Detail) -> pb::WalletError {
    pb::WalletError {
        reason: reason.into(),
        detail: Some(detail),
        ..pb::WalletError::default()
    }
}

/// Convert a raw protobuf enum discriminant into a known wallet reason.
pub fn error_reason_from_i32(value: i32) -> Result<WalletErrorReason, ConvertErrorReason> {
    WalletErrorReason::from_i32(value).ok_or(ConvertErrorReason::InvalidEnumValue)
}

/// Convert a generated enum wrapper into a known wallet reason.
pub fn error_reason_from_enum_value(
    value: EnumValue<WalletErrorReason>,
) -> Result<WalletErrorReason, ConvertErrorReason> {
    value.as_known().ok_or(ConvertErrorReason::InvalidEnumValue)
}

/// Return the stable unsigned reason code carried by stack error envelopes.
#[must_use]
pub fn error_reason_code(reason: WalletErrorReason) -> u32 {
    match u32::try_from(reason.to_i32()) {
        Ok(code) => code,
        Err(_) => WalletErrorReason::WALLET_ERROR_REASON_UNSPECIFIED
            .to_i32()
            .unsigned_abs(),
    }
}

/// Build the shared ReallyMe stack envelope for a wallet-owned reason.
///
/// The caller owns correlation-id policy and must pass only non-PII opaque
/// identifiers. Keeping this helper in the facade avoids generated-code
/// dependencies in the wallet member crates.
#[must_use]
pub fn identity_stack_error_from_reason(
    reason: WalletErrorReason,
    correlation_id: Option<&str>,
) -> IdentityStackError {
    IdentityStackError {
        domain: WALLET_DOMAIN.into(),
        reason_code: error_reason_code(reason),
        correlation_id: correlation_id.unwrap_or_default().to_owned(),
        ..IdentityStackError::default()
    }
}

/// Extract and validate a wallet reason from a shared ReallyMe stack envelope.
pub fn error_reason_from_identity_stack_error(
    error: &IdentityStackError,
) -> Result<WalletErrorReason, ConvertErrorReason> {
    if error.domain.as_known() != Some(WALLET_DOMAIN) {
        return Err(ConvertErrorReason::InvalidEnumValue);
    }
    let reason_code =
        i32::try_from(error.reason_code).map_err(|_| ConvertErrorReason::InvalidEnumValue)?;
    error_reason_from_i32(reason_code)
}

/// Build the generated wallet-specific envelope used at runtime and SDK edges.
#[must_use]
pub fn wallet_error_envelope_from_error(
    error: pb::WalletError,
    correlation_id: Option<&str>,
) -> pb::WalletErrorEnvelope {
    let reason = error
        .reason
        .as_known()
        .unwrap_or(WalletErrorReason::WALLET_ERROR_REASON_UNSPECIFIED);
    pb::WalletErrorEnvelope {
        stack: MessageField::some(identity_stack_error_from_reason(reason, correlation_id)),
        wallet: MessageField::some(error),
        ..pb::WalletErrorEnvelope::default()
    }
}

#[path = "map_adapter_reasons.rs"]
mod map_adapter_reasons;
#[path = "map_domain_details.rs"]
mod map_domain_details;
#[path = "map_domain_reasons.rs"]
mod map_domain_reasons;

pub use map_adapter_reasons::{
    convert_error_to_proto, map_convert_detail_reason, map_convert_error_reason,
    map_proto_detail_reason, map_proto_error_reason, map_runtime_detail_reason,
    map_runtime_error_reason, proto_error_to_proto, runtime_error_to_proto,
};
#[cfg(feature = "render")]
pub use map_adapter_reasons::{
    map_render_detail_reason, map_render_error_reason, render_error_to_proto,
};
pub use map_domain_details::{
    attestation_error_to_proto, consent_error_to_proto, inventory_error_to_proto,
    keystore_error_to_proto, lifecycle_error_to_proto, log_error_to_proto,
    map_attestation_detail_reason, map_consent_detail_reason, map_inventory_detail_reason,
    map_keystore_detail_reason, map_lifecycle_detail_reason, map_log_detail_reason,
    map_storage_detail_reason, map_wallet_types_detail_reason, storage_error_to_proto,
    wallet_types_error_to_proto,
};
pub use map_domain_reasons::{
    flow_error_to_proto, map_attestation_error_reason, map_consent_error_reason,
    map_flow_detail_reason, map_flow_error_reason, map_inventory_error_reason,
    map_keystore_error_reason, map_lifecycle_error_reason, map_log_error_reason,
    map_storage_error_reason, map_wallet_types_error_reason,
};
