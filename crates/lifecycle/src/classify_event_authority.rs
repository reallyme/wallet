// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Classify lifecycle events by the authority their evidence must carry.

use crate::WalletLifecycleEvent;

/// Return whether `event` requires authenticated lifecycle authority.
///
/// Restrictive transitions can deny service or irreversibly withdraw or delete
/// a Wallet Unit. They need authority just as transitions that grant access do.
/// Beginning initial provisioning is the sole exception because an
/// unprovisioned record has no live capabilities or credential data to lose.
#[must_use]
pub const fn lifecycle_event_requires_verified_authority(event: WalletLifecycleEvent) -> bool {
    match event {
        WalletLifecycleEvent::BeginProvisioning => false,
        WalletLifecycleEvent::CompleteProvisioning
        | WalletLifecycleEvent::Suspend
        | WalletLifecycleEvent::Reactivate
        | WalletLifecycleEvent::BeginRecovery
        | WalletLifecycleEvent::CompleteRecovery
        | WalletLifecycleEvent::BeginMigration
        | WalletLifecycleEvent::CompleteMigration
        | WalletLifecycleEvent::BeginWithdrawal
        | WalletLifecycleEvent::CompleteWithdrawal
        | WalletLifecycleEvent::BeginDeletion
        | WalletLifecycleEvent::CompleteDeletion
        | WalletLifecycleEvent::MarkFailed
        | WalletLifecycleEvent::RetryProvisioning => true,
    }
}

#[cfg(test)]
#[path = "classify_event_authority_tests.rs"]
mod tests;
