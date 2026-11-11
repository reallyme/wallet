// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical policy persistence. Codecs check bounded wire shape; owning domain
//! operations additionally check authenticated state, hashes, and trusted time.
//! Decoded evidence never reconstructs an authorization capability.

#[path = "policy_records/codec.rs"]
mod codec;
#[path = "policy_records/execution.rs"]
mod execution;
#[path = "policy_records/history.rs"]
mod history;
#[path = "policy_records/receipt.rs"]
mod receipt;
#[path = "policy_records/reuse.rs"]
mod reuse;

pub use execution::{decode_flow_execution_record, encode_flow_execution_record};
pub use history::{decode_transaction_history_record, encode_transaction_history_record};
pub use receipt::{decode_consent_receipt, encode_consent_receipt};
pub use reuse::{decode_credential_reuse_state, encode_credential_reuse_state};

#[cfg(test)]
#[path = "policy_records_tests.rs"]
mod tests;

/// Maximum canonical policy persistence record before provider encryption.
pub const MAX_POLICY_RECORD_BYTES: usize = 4_194_304;
