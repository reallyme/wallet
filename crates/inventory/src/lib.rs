// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential lifecycle and batch-pool ownership.
//!
//! Batch pools select once-only presentation copies within one in-memory
//! inventory snapshot. A holder-private prepared token must be claimed through
//! a durable `PresentationCopyStore` before its proof or signing key is exposed;
//! in-memory selection alone cannot preserve the burn across a crash.

mod check_status_list;
mod claim;
mod delete;
mod error;
mod import;
mod refresh;
mod reissue;
mod update_status;
mod validate_record;

pub use check_status_list::apply_token_status_list;
pub use claim::BatchPool;
pub use delete::delete_credential_record;
pub use error::{InventoryError, InventoryErrorReason, InventoryResult};
pub use import::import_validated_credential;
pub use reissue::reissue_credential_record;

mod enforce_reuse;
mod retire_reuse_instance;
pub use enforce_reuse::{
    claim_credential_use, create_reuse_cohort, evaluate_replenishment, fulfill_replenishment,
    request_replenishment, validate_reuse_state, ReplenishmentDecision, ReuseError,
    ReuseErrorReason,
};
pub use retire_reuse_instance::retire_reuse_instance;
