// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public facade for the ReallyMe EUDI wallet core.
//!
//! The facade intentionally re-exports wallet-owned boundaries only. Protocol
//! wire parsing stays in the OpenID and identity repositories; platform storage,
//! secure elements, network transports, and user interaction remain injected
//! through traits owned by the member crates.

/// Map wallet-owned Rust error reasons to generated protobuf reason codes.
#[cfg(feature = "native")]
pub mod map_error_reason;

pub use reallyme_wallet_attestation as attestation;
pub use reallyme_wallet_consent as consent;
pub use reallyme_wallet_flows as flows;
#[cfg(feature = "http")]
pub use reallyme_wallet_http as http;
pub use reallyme_wallet_inventory as inventory;
pub use reallyme_wallet_keystore as keystore;
pub use reallyme_wallet_lifecycle as lifecycle;
pub use reallyme_wallet_log as log;
pub use reallyme_wallet_proto as proto;
pub use reallyme_wallet_proto_codec as proto_codec;
pub use reallyme_wallet_provider as provider;
#[cfg(feature = "render")]
pub use reallyme_wallet_render as render;
pub use reallyme_wallet_runtime as runtime;
pub use reallyme_wallet_storage as storage;
pub use reallyme_wallet_types as types;
