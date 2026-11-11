// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Time and lifecycle rules for transaction-log and QTSP audit records.

use reallyme_wallet_lifecycle::WalletOperation;
use reallyme_wallet_types::{TransactionPurpose, UnixTimestamp};

use crate::{RuntimeError, RuntimeErrorReason, RuntimeResult};

/// Largest amount a caller-dated audit record may run ahead of trusted time.
///
/// Records are dated on the device, whose clock may differ slightly from the
/// trusted clock; anything further ahead claims an event that has not happened.
pub(crate) const MAX_AUDIT_RECORD_CLOCK_SKEW_SECONDS: i64 = 60;

/// Refuse an audit record dated beyond the accepted skew from `trusted_now`.
pub(crate) fn require_record_time(
    recorded_at: UnixTimestamp,
    trusted_now: UnixTimestamp,
) -> RuntimeResult<()> {
    let latest = trusted_now
        .as_seconds()
        .checked_add(MAX_AUDIT_RECORD_CLOCK_SKEW_SECONDS)
        .ok_or(RuntimeError::new(RuntimeErrorReason::RecordClockSkew))?;
    if recorded_at.as_seconds() > latest {
        return Err(RuntimeError::new(RuntimeErrorReason::RecordClockSkew));
    }
    Ok(())
}

/// Lifecycle operation that gates appending a transaction-log entry.
///
/// Deletion entries record erasure, which a withdrawn or deleted Wallet Unit
/// may still perform, so they follow the deletion rule rather than the rule
/// for new history.
pub(crate) const fn transaction_history_operation(purpose: TransactionPurpose) -> WalletOperation {
    match purpose {
        TransactionPurpose::Deletion => WalletOperation::DeleteWallet,
        TransactionPurpose::Issuance
        | TransactionPurpose::Presentation
        | TransactionPurpose::Refresh => WalletOperation::RecordTransactionHistory,
    }
}
