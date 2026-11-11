// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet Unit lifecycle state machine.
//!
//! This crate owns lifecycle policy consumed by native Rust and downstream SDK
//! facades. It deliberately exposes typed records and transition helpers only;
//! persistence, prompts, and platform secure-area integrations are injected by
//! higher layers.

mod authorize_operation;
mod classify_event_authority;
mod error;
mod model;
mod reconcile_retry;
mod transition;
mod validate_evidence;

pub use authorize_operation::ensure_wallet_operation_allowed;
pub use classify_event_authority::lifecycle_event_requires_verified_authority;
pub use error::{LifecycleError, LifecycleErrorReason, LifecycleResult};
pub use model::{
    WalletLifecycleEvent, WalletLifecycleEvidenceKind, WalletLifecycleEvidenceRecord,
    WalletLifecycleRecord, WalletLifecycleState, WalletOperation,
};
pub use reconcile_retry::{is_wallet_lifecycle_retry, ReconciledWalletLifecycleRetry};
pub use transition::{
    apply_reconciled_wallet_lifecycle_retry, apply_wallet_lifecycle_event, new_wallet_lifecycle,
    restore_wallet_lifecycle, validate_wallet_lifecycle_successor,
};
pub use validate_evidence::{
    validate_wallet_lifecycle_evidence_record, MAX_LIFECYCLE_EVIDENCE_DIGEST_LEN,
};
