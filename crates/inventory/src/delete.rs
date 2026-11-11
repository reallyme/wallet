// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mark credential records deleted in local wallet inventory.

use reallyme_wallet_types::{CredentialRecord, CredentialStatusUpdate};

/// Mark a credential deleted before or after platform storage removes ciphertext.
///
/// Local deletion is terminal for wallet lifecycle decisions. The platform SDK
/// still owns physical encrypted-record deletion; this transition records the
/// wallet-visible state used by logs, sync, and conflict resolution.
#[must_use]
pub fn delete_credential_record(record: &mut CredentialRecord) -> CredentialStatusUpdate {
    record.mark_deleted()
}

#[cfg(test)]
#[path = "delete_tests.rs"]
mod tests;
