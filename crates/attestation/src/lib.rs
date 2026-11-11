// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet unit attestation lifecycle.

mod error;
mod model;
mod obtain;
mod rotate;
mod validate;

pub use error::{AttestationError, AttestationErrorReason, AttestationResult};
pub use model::{
    UnverifiedWalletUnitAttestation, VerifiedWalletKeyThumbprint, WalletUnitAttestation,
};
pub use obtain::{
    obtain_wallet_unit_attestation, verify_wallet_unit_attestation,
    verify_wallet_unit_attestation_for_key, WalletUnitAttestationProvider,
    WalletUnitAttestationVerifier,
};
pub use rotate::rotate_wallet_unit_attestation;
pub use validate::validate_wallet_unit_attestation;
