// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent bounded command programs exercise the public Wallet boundaries.
#![cfg(feature = "native")]

#[path = "state_machine_models/sequence_tests.rs"]
mod models;

#[test]
fn generated_programs_preserve_security_state_invariants() -> Result<(), models::ModelError> {
    for seed in 1_u32..=256 {
        let mut generator = seed;
        let mut program = [0_u8; models::MAX_PROGRAM_BYTES];
        for byte in &mut program {
            generator ^= generator << 13;
            generator ^= generator >> 17;
            generator ^= generator << 5;
            *byte = generator.to_le_bytes()[0];
        }
        assert!(models::exercise(&program)?);
    }
    Ok(())
}

#[test]
fn oversized_programs_are_refused_before_executing_commands() -> Result<(), models::ModelError> {
    assert!(models::exercise(&[])?);
    assert!(!models::exercise(&[0xff; models::MAX_PROGRAM_BYTES + 1])?);
    Ok(())
}

#[test]
fn lifecycle_and_delivery_regression_programs_remain_covered() -> Result<(), models::ModelError> {
    for commands in [
        &[0, 1, 2, 4, 12, 4, 5, 3, 6, 7, 8, 9, 10, 11][..],
        &[0, 1, 6, 12, 6, 7, 10, 12, 10, 11][..],
        &[0, 3, 1, 3, 2, 4, 8, 5, 6, 7][..],
    ] {
        let program = commands
            .iter()
            .flat_map(|command| [*command, *command, 1, 8])
            .collect::<Vec<_>>();
        assert!(models::exercise(&program)?);
    }
    Ok(())
}

#[test]
fn flow_effect_capacity_never_evicts_prior_reservations() -> Result<(), models::ModelError> {
    let mut program = Vec::new();
    for identity in 1_u8..=33 {
        program.extend_from_slice(&[0, identity, 1, 0]);
        program.extend_from_slice(&[3, identity, 1, 0]);
    }
    assert!(models::exercise(&program)?);
    Ok(())
}

#[test]
fn fulfilled_replenishment_never_reopens_the_retired_cohort() -> Result<(), models::ModelError> {
    // Three once-only claims reach the replenishment threshold. The provider
    // then fulfills that exact intent; the remaining old copy stays retired.
    let program = [
        0, 1, 1, 1, 0, 2, 2, 1, 0, 3, 3, 1, 2, 4, 4, 1, 3, 4, 4, 1, 0, 5, 5, 1,
    ];
    assert!(models::exercise(&program)?);
    Ok(())
}
