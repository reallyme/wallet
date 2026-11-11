// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable storage port for encrypted preparation and request or public output.

use reallyme_wallet_types::{CredentialRecordId, RecordRevision, Versioned};
use reallyme_wallet_zk::ZkStoredArtifactRecord;

use crate::StorageResult;

/// Read-only platform port for encrypted ZK material linked to inventory.
///
/// Separating reads from mutation lets the presentation path accept a store
/// that cannot accidentally create or delete credential material while a
/// verifier request is being processed.
pub trait ZkArtifactReader {
    /// Load and validate one stored record together with its revision.
    fn get_zk_artifact(
        &self,
        artifact_id: &[u8; 32],
    ) -> StorageResult<Versioned<ZkStoredArtifactRecord>>;
}

/// Platform store for encrypted ZK material linked to credential inventory.
///
/// Storage must persist the canonical bounded Wallet Buffa encoding, enforce
/// unique artifact ids, and keep the descriptor's AEAD AAD unchanged. Reading
/// an artifact is not authorization to present: the caller must check current
/// credential lifecycle, issuer status, active request, and final disclosure.
/// Private prepared proof packages must use `PresentationCopyStore` so their
/// one-time token is durably reserved before any bytes or key handle leave.
pub trait ZkArtifactStore: ZkArtifactReader {
    /// Atomically create one artifact, rejecting any existing identifier.
    fn create_zk_artifact(
        &mut self,
        artifact: ZkStoredArtifactRecord,
    ) -> StorageResult<RecordRevision>;

    /// Compare-and-delete one expired or consumed request artifact.
    fn delete_zk_artifact(
        &mut self,
        artifact_id: &[u8; 32],
        expected_revision: RecordRevision,
    ) -> StorageResult<()>;

    /// Atomically remove a credential and all artifacts linked to it.
    ///
    /// An adapter must never leave reusable private inputs or old proofs
    /// orphaned after credential deletion. Revision mismatch aborts the whole
    /// operation without modifying either inventory or artifacts.
    fn delete_credential_and_zk_artifacts(
        &mut self,
        credential_id: &CredentialRecordId,
        expected_credential_revision: RecordRevision,
    ) -> StorageResult<()>;
}
