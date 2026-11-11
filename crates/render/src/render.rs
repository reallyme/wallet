// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Render wallet cards into platform distribution artifacts.

use reallyme_wallet_types::DistributionCard;

use crate::RenderResult;

/// Renderer for user-facing wallet artifacts.
pub trait WalletRenderer {
    /// Render a wallet card into target-specific bytes.
    fn render_card(&self, card: &DistributionCard) -> RenderResult<Vec<u8>>;
}
