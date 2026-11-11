// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the canonical Wallet ProtoJSON boundary on arbitrary UTF-8 input.
//! Property: duplicate keys, excessive nesting, malformed shapes, unknown
//! enums, and oversized values must fail with typed errors and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1::{
    WalletOperationRequest, WalletOperationResponse, WalletOperationResult,
};
use reallyme_wallet_proto_codec::wallet_proto_from_json;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = core::str::from_utf8(data) else {
        return;
    };

    let _ = wallet_proto_from_json::<WalletOperationRequest>(json);
    let _ = wallet_proto_from_json::<WalletOperationResult>(json);
    let _ = wallet_proto_from_json::<WalletOperationResponse>(json);
});
