// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict Wallet protobuf and ProtoJSON codecs.
//!
//! Generated messages intentionally live in `reallyme-wallet-proto`. This crate
//! owns every operation that interprets protobuf bytes, ProtoJSON, enums, or
//! generated message fields as validated Wallet domain data.

#[cfg(not(any(feature = "native", feature = "wasm")))]
compile_error!(
    "reallyme-wallet-proto-codec requires either the `native` or `wasm` runtime feature"
);

/// Validated generated-message/domain conversions.
pub mod convert;
/// Decode protobuf bytes into validated domain values.
pub mod decode;
/// Encode validated domain values into bounded protobuf bytes.
pub mod encode;
mod error;
mod key_storage;
mod key_storage_hardware;
mod limits;
#[cfg(feature = "zk")]
pub mod prepared_private_token;
mod proto_json;
#[cfg(feature = "zk")]
pub mod zk_artifact;

pub use error::{
    map_proto_detail_reason, map_proto_error_reason, proto_error_to_proto, ProtoError,
    ProtoErrorReason, ProtoResult,
};
pub use key_storage::{
    validate_did_storage_record, validate_hardware_key_binding_record,
    validate_portable_key_storage_record,
};
pub use limits::{
    MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES, MAX_WALLET_PROTO_JSON_BYTES,
    MAX_WALLET_PROTO_JSON_NESTING_DEPTH, MAX_WALLET_PROTO_MESSAGE_BYTES,
    MAX_WALLET_PROTO_RECURSION_DEPTH, MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES,
    WALLET_PROTO_UNKNOWN_FIELD_LIMIT,
};
pub use proto_json::{wallet_proto_from_json, wallet_proto_to_json, WalletProtoJson};

/// Canonical persistence codecs for reuse, receipts, history and execution guards.
pub mod policy_records;
