// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable issuer-metadata policy selected by the wallet composer.

/// Issuer-metadata profile enforced before an OpenID4VCI session starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenId4VciIssuerMetadataProfile {
    /// OpenID4VCI metadata without additional ETSI Part 3 requirements.
    OpenId4Vci,
    /// ETSI TS 119 472-3 metadata with authenticated registrar data.
    EtsiTs119472Part3,
    /// The EU legal Part 3 adaptation, including a registration certificate.
    EuEtsiTs119472Part3,
}
