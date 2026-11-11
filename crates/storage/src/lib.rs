// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage traits for platform-provided encrypted wallet stores.

mod consent_capture;
mod credential_dispatch;
mod error;
mod journal;
mod store;
#[cfg(feature = "zk")]
mod zk_artifact_store;

pub use consent_capture::{
    ConsentCaptureStore, ConsentCaptureStoreError, ConsentCaptureStoreErrorReason, ConsentClaim,
};
pub use credential_dispatch::{CredentialDispatchStore, MAX_CREDENTIAL_DISPATCH_BYTES};
pub use error::{StorageError, StorageErrorReason, StorageResult};
pub use journal::{
    OperationIdempotencyKey, OperationJournal, OperationReplayDecision, OperationRequestDigest,
    OperationReservation, OPERATION_IDEMPOTENCY_KEY_LENGTH,
};
pub use store::{
    CredentialRecordStore, FlowSnapshotStore, OpenId4VciIssuanceCommitResult,
    OpenId4VciIssuanceCommitStore, PreparedZkPresentationCopyStore, PresentationCopyClaimPolicy,
    PresentationCopyStore, QtspDecisionStore, TransactionLogStore, VersionedEncryptedRecord,
    VersionedFlowSnapshot, VersionedOpenId4VciNotificationOutboxEntry,
    VersionedWalletLifecycleRecord, WalletLifecycleStore,
};
#[cfg(feature = "zk")]
pub use zk_artifact_store::{ZkArtifactReader, ZkArtifactStore};

mod policy;
pub use policy::{CredentialReuseStore, FlowExecutionStore, TransactionHistoryStore};
