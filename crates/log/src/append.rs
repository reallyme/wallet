// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Append user-visible wallet transaction log records.

use reallyme_wallet_types::{QtspDecisionRecord, TransactionLogEntry};

use crate::WalletLogResult;
use crate::{validate_qtsp_decision_record, validate_transaction_log_entry};

/// Append-only wallet log.
pub trait WalletTransactionLog {
    /// Compare the durable head and append a unique entry atomically.
    fn append_transaction(&mut self, entry: TransactionLogEntry) -> WalletLogResult<()>;

    /// Append a QTSP or qualified trust decision record.
    fn append_qtsp_decision(&mut self, record: QtspDecisionRecord) -> WalletLogResult<()>;
}

/// Validate and append a user-visible transaction entry.
pub fn append_transaction_entry<L>(log: &mut L, entry: TransactionLogEntry) -> WalletLogResult<()>
where
    L: WalletTransactionLog,
{
    validate_transaction_log_entry(&entry)?;
    log.append_transaction(entry)
}

/// Validate and append a QTSP or qualified-trust decision record.
pub fn append_qtsp_decision_record<L>(
    log: &mut L,
    record: QtspDecisionRecord,
) -> WalletLogResult<()>
where
    L: WalletTransactionLog,
{
    validate_qtsp_decision_record(&record)?;
    log.append_qtsp_decision(record)
}
