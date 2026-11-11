// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic resource limits for Wallet protobuf boundaries.

/// Maximum accepted or generated Wallet protobuf message size.
///
/// Adapters may impose a tighter limit, but no public codec path may accept a
/// larger message. The value accommodates credential and presentation payloads
/// without allowing unbounded allocation from hostile length-delimited fields.
pub const MAX_WALLET_PROTO_MESSAGE_BYTES: usize = 2_097_152;

/// Maximum accepted or generated provider-contract protobuf message size.
///
/// Provider responses can wrap a maximum-size canonical operation response for
/// exact replay. The additional 64 KiB is a fixed ceiling for the version,
/// correlation, result, and replay envelopes rather than an unbounded margin.
pub const MAX_WALLET_PROVIDER_PROTO_MESSAGE_BYTES: usize = 2_162_688;

/// Maximum accepted or generated Wallet ProtoJSON size.
///
/// This permits base64 expansion of the protobuf limit while retaining a fixed
/// resource ceiling for JSON-only SDK callers.
pub const MAX_WALLET_PROTO_JSON_BYTES: usize = 3_145_728;

/// Maximum protobuf and ProtoJSON nesting depth accepted by Wallet codecs.
pub const MAX_WALLET_PROTO_RECURSION_DEPTH: u32 = 64;

/// Maximum memory a binary decode may allocate for repeated message elements.
///
/// Four times the largest provider message bounds the amplification from many
/// small repeated submessages instead of relying on the decoder default.
pub const MAX_WALLET_PROTO_ELEMENT_MEMORY_BYTES: usize = 8_650_752;

/// Maximum nesting depth accepted by Wallet ProtoJSON parsing.
pub const MAX_WALLET_PROTO_JSON_NESTING_DEPTH: usize = 64;

/// Maximum unknown protobuf fields materialized at the canonical boundary.
///
/// Versioned operation envelopes reject unknown fields so an older executor
/// cannot silently ignore a security-relevant command or policy input.
pub const WALLET_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;

/// Maximum repeated identifiers accepted in a single wallet message.
pub const MAX_WALLET_REPEATED_IDENTIFIERS: usize = 1_024;
