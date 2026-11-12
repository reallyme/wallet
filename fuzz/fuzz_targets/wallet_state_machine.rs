// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded command programs challenge lifecycle, flow and reuse invariants.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../conformance/tests/state_machine_models/sequence_tests.rs"]
mod models;

fuzz_target!(|program: &[u8]| models::fuzz(program));
