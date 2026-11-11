// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_wallet_types::NonEmptyIdentifier;

use super::OpenId4VciAccessTokenHandle;
use crate::OpenId4VciIssuanceSession;

pub(crate) fn token_handle_for_session(
    id: NonEmptyIdentifier,
    session: &OpenId4VciIssuanceSession,
) -> OpenId4VciAccessTokenHandle {
    OpenId4VciAccessTokenHandle {
        id,
        credential_issuer: Some(session.credential_issuer.clone()),
    }
}
