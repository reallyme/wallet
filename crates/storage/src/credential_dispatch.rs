// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable reservation of final issuer request bytes before transport.

use crate::StorageResult;
use zeroize::Zeroizing;

/// Maximum final request payload a store must accept for one attempt.
pub const MAX_CREDENTIAL_DISPATCH_BYTES: usize = 2_097_152;

/// Store exact issuer request bytes as a write-once issuance attempt.
pub trait CredentialDispatchStore: Send + Sync {
    /// Atomically create the protected record. A second claim for the same
    /// attempt is a conflict, even if its bytes match. A previous reservation
    /// means delivery may have occurred and requires reconciliation.
    fn reserve_credential_dispatch(
        &self,
        attempt: &[u8; 32],
        launch_digest: &[u8; 32],
        wire_request: &[u8],
    ) -> StorageResult<()>;

    /// Read the authenticated exact bytes for the same attempt and launch.
    /// A different launch under an existing attempt is an idempotency conflict.
    fn load_credential_dispatch(
        &self,
        attempt: &[u8; 32],
        launch_digest: &[u8; 32],
    ) -> StorageResult<Option<Zeroizing<Vec<u8>>>>;
}
