// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::lifecycle_event_requires_verified_authority;
use crate::WalletLifecycleEvent;

#[test]
fn every_event_after_initial_provisioning_requires_verified_authority() {
    for event in [
        WalletLifecycleEvent::CompleteProvisioning,
        WalletLifecycleEvent::Suspend,
        WalletLifecycleEvent::Reactivate,
        WalletLifecycleEvent::BeginRecovery,
        WalletLifecycleEvent::CompleteRecovery,
        WalletLifecycleEvent::BeginMigration,
        WalletLifecycleEvent::CompleteMigration,
        WalletLifecycleEvent::BeginWithdrawal,
        WalletLifecycleEvent::CompleteWithdrawal,
        WalletLifecycleEvent::BeginDeletion,
        WalletLifecycleEvent::CompleteDeletion,
        WalletLifecycleEvent::MarkFailed,
        WalletLifecycleEvent::RetryProvisioning,
    ] {
        assert!(lifecycle_event_requires_verified_authority(event));
    }
}

#[test]
fn beginning_initial_provisioning_needs_no_authority() {
    assert!(!lifecycle_event_requires_verified_authority(
        WalletLifecycleEvent::BeginProvisioning
    ));
}
