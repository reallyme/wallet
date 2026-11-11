// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! User-visible transaction and QTSP decision log boundary.

mod append;
mod error;
mod validate;

pub use append::{append_qtsp_decision_record, append_transaction_entry, WalletTransactionLog};
pub use error::{WalletLogError, WalletLogErrorReason, WalletLogResult};
pub use validate::{
    chain_transaction_log_entry, validate_qtsp_decision_record, validate_transaction_log_chain,
    validate_transaction_log_chain_to_head, validate_transaction_log_entry,
    MAX_TRANSACTION_LOG_DISCLOSED_ATTRIBUTES,
};

mod history;
pub use history::{
    append_history_record, chain_history_record, export_history_page, validate_history_metadata,
    validate_history_record, HistoryError, HistoryErrorReason,
};
