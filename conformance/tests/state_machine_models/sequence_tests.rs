// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only reference models shared by deterministic tests and libFuzzer.

#[path = "flow_model_tests.rs"]
mod flow_model_tests;
#[path = "lifecycle_model_tests.rs"]
mod lifecycle_model_tests;
#[path = "reuse_model_tests.rs"]
mod reuse_model_tests;

use reallyme_wallet::types::{UnixTimestamp, WalletTypesError};

pub const MAX_PROGRAM_BYTES: usize = 512;
const COMMAND_BYTES: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("wallet_types")]
    Types(#[from] WalletTypesError),
    #[error("fixture_arithmetic")]
    Arithmetic,
    #[error("flow_fixture")]
    Flow(#[from] reallyme_wallet::flows::ExecutionError),
    #[error("reuse_fixture")]
    Reuse(#[from] reallyme_wallet::inventory::ReuseError),
    #[error("lifecycle_fixture")]
    Lifecycle(#[from] reallyme_wallet::lifecycle::LifecycleError),
}

pub fn time(seconds: i64) -> Result<UnixTimestamp, ModelError> {
    Ok(UnixTimestamp::from_seconds(seconds)?)
}

/// The cap is checked before allocating state or traversing the input.
pub fn exercise(program: &[u8]) -> Result<bool, ModelError> {
    if program.len() > MAX_PROGRAM_BYTES {
        return Ok(false);
    }
    let (commands, _) = program.as_chunks::<COMMAND_BYTES>();
    flow_model_tests::exercise(commands)?;
    lifecycle_model_tests::exercise(commands)?;
    reuse_model_tests::exercise(commands)?;
    Ok(true)
}

// This assertion is test code, not part of any public Wallet crate. A model
// disagreement must stop libFuzzer so it retains the counterexample input.
#[allow(dead_code)]
pub fn fuzz(program: &[u8]) {
    assert!(exercise(program).is_ok());
}
