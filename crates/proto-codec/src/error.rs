// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for wallet protobuf operations.

use buffa::DecodeError;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use thiserror::Error;

/// Result type for wallet DTO codec operations.
pub type ProtoResult<T> = Result<T, ProtoError>;

/// Typed proto codec error with stable reason codes.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("wallet proto codec operation failed: {reason}")]
pub struct ProtoError {
    /// Stable reason code.
    pub reason: ProtoErrorReason,
}

impl ProtoError {
    /// Construct a proto codec error from a stable reason.
    #[must_use]
    pub const fn new(reason: ProtoErrorReason) -> Self {
        Self { reason }
    }
}

/// Stable proto codec failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtoErrorReason {
    /// Encoded DTO did not match the supported schema.
    #[error("unsupported_schema")]
    UnsupportedSchema,
    /// Encoded bytes ended before a complete protobuf value was available.
    #[error("truncated_input")]
    TruncatedInput,
    /// Encoded bytes contained malformed protobuf wire data.
    #[error("malformed_wire")]
    MalformedWire,
    /// Encoded message exceeded the configured protobuf decode limits.
    #[error("message_too_large")]
    MessageTooLarge,
    /// Encoded message exceeded the configured protobuf recursion limit.
    #[error("recursion_limit_exceeded")]
    RecursionLimitExceeded,
    /// Encoded message exceeded the configured unknown-field materialization limit.
    #[error("unknown_field_limit_exceeded")]
    UnknownFieldLimitExceeded,
    /// Encoded string data was not valid UTF-8.
    #[error("invalid_utf8")]
    InvalidUtf8,
    /// DTO failed validation after decoding.
    #[error("invalid_dto")]
    InvalidDto,
    /// Generated ProtoJSON could not be serialized within boundary policy.
    #[error("json_serialize")]
    JsonSerialize,
    /// ProtoJSON was malformed or did not match the generated message contract.
    #[error("json_deserialize")]
    JsonDeserialize,
    /// ProtoJSON contained a duplicate object key.
    #[error("json_duplicate_key")]
    JsonDuplicateKey,
    /// ProtoJSON exceeded the configured nesting depth.
    #[error("json_nesting_too_deep")]
    JsonNestingTooDeep,
}

impl From<DecodeError> for ProtoError {
    fn from(error: DecodeError) -> Self {
        let reason = match error {
            DecodeError::UnexpectedEof => ProtoErrorReason::TruncatedInput,
            DecodeError::MessageTooLarge | DecodeError::ElementMemoryLimitExceeded => {
                ProtoErrorReason::MessageTooLarge
            }
            DecodeError::RecursionLimitExceeded => ProtoErrorReason::RecursionLimitExceeded,
            DecodeError::UnknownFieldLimitExceeded => ProtoErrorReason::UnknownFieldLimitExceeded,
            DecodeError::InvalidUtf8 => ProtoErrorReason::InvalidUtf8,
            DecodeError::VarintTooLong
            | DecodeError::InvalidWireType(_)
            | DecodeError::InvalidFieldNumber
            | DecodeError::WireTypeMismatch { .. }
            | DecodeError::InvalidEndGroup(_)
            | DecodeError::InvalidMessageSet(_)
            | DecodeError::Custom(_)
            | _ => ProtoErrorReason::MalformedWire,
        };

        Self::new(reason)
    }
}

impl From<crate::convert::ConvertError> for ProtoError {
    fn from(_error: crate::convert::ConvertError) -> Self {
        Self::new(ProtoErrorReason::InvalidDto)
    }
}

/// Map protobuf codec reasons to the stable public Wallet reason taxonomy.
#[must_use]
pub const fn map_proto_error_reason(reason: ProtoErrorReason) -> pb::WalletErrorReason {
    match reason {
        ProtoErrorReason::UnsupportedSchema => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_UNSUPPORTED_SCHEMA
        }
        ProtoErrorReason::TruncatedInput
        | ProtoErrorReason::MalformedWire
        | ProtoErrorReason::InvalidUtf8
        | ProtoErrorReason::JsonDeserialize
        | ProtoErrorReason::JsonDuplicateKey => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_MALFORMED_WIRE
        }
        ProtoErrorReason::MessageTooLarge
        | ProtoErrorReason::RecursionLimitExceeded
        | ProtoErrorReason::UnknownFieldLimitExceeded
        | ProtoErrorReason::JsonNestingTooDeep => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_PROTO_LIMIT_EXCEEDED
        }
        ProtoErrorReason::InvalidDto => pb::WalletErrorReason::WALLET_ERROR_REASON_INVALID_INPUT,
        ProtoErrorReason::JsonSerialize => {
            pb::WalletErrorReason::WALLET_ERROR_REASON_SERIALIZATION_FAILED
        }
    }
}

/// Map protobuf codec reasons to their exact generated detail discriminants.
#[must_use]
pub const fn map_proto_detail_reason(reason: ProtoErrorReason) -> pb::ProtoErrorReason {
    match reason {
        ProtoErrorReason::UnsupportedSchema => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_UNSUPPORTED_SCHEMA
        }
        ProtoErrorReason::TruncatedInput => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_TRUNCATED_INPUT
        }
        ProtoErrorReason::MalformedWire => pb::ProtoErrorReason::PROTO_ERROR_REASON_MALFORMED_WIRE,
        ProtoErrorReason::MessageTooLarge => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_MESSAGE_TOO_LARGE
        }
        ProtoErrorReason::RecursionLimitExceeded => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_RECURSION_LIMIT_EXCEEDED
        }
        ProtoErrorReason::UnknownFieldLimitExceeded => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_UNKNOWN_FIELD_LIMIT_EXCEEDED
        }
        ProtoErrorReason::InvalidUtf8 => pb::ProtoErrorReason::PROTO_ERROR_REASON_INVALID_UTF8,
        ProtoErrorReason::InvalidDto => pb::ProtoErrorReason::PROTO_ERROR_REASON_INVALID_DTO,
        ProtoErrorReason::JsonSerialize => pb::ProtoErrorReason::PROTO_ERROR_REASON_JSON_SERIALIZE,
        ProtoErrorReason::JsonDeserialize => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_JSON_DESERIALIZE
        }
        ProtoErrorReason::JsonDuplicateKey => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_JSON_DUPLICATE_KEY
        }
        ProtoErrorReason::JsonNestingTooDeep => {
            pb::ProtoErrorReason::PROTO_ERROR_REASON_JSON_NESTING_TOO_DEEP
        }
    }
}

/// Build the privacy-safe generated Wallet error for a protobuf codec failure.
#[must_use]
pub fn proto_error_to_proto(reason: ProtoErrorReason) -> pb::WalletError {
    pb::WalletError {
        reason: map_proto_error_reason(reason).into(),
        detail: Some(pb::wallet_error::Detail::Proto(
            map_proto_detail_reason(reason).into(),
        )),
        ..Default::default()
    }
}
