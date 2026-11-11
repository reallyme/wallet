// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host-injected trusted time for provider-backed runtime security gates.

use reallyme_wallet_types::UnixTimestamp;

use crate::ProviderHostCapabilityError;

/// Trusted current time supplied by the host that composes the provider.
///
/// The runtime uses this value to bound lifecycle evidence age and other
/// time-dependent checks. Implementations must source time the host trusts
/// for security decisions, such as a platform secure clock or an
/// authenticated time service. A user-adjustable device clock is not a
/// trusted source. The provider backend never reads the system clock: it
/// uses this injected clock when one is attached, and otherwise asks the
/// provider through `ReadTrustedTime`, which must answer from an equally
/// trusted source or fail. A transport that cannot answer fails closed.
pub trait ProviderTrustedClock: Send + Sync {
    /// Return trusted current time or a typed failure.
    fn trusted_now(&self) -> Result<UnixTimestamp, ProviderHostCapabilityError>;
}
