// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport-neutral protobuf operation runtime for wallet SDK adapters.
//!
//! This crate owns generated-protobuf request handling. Native HTTP adapters
//! live in the sibling `reallyme-wallet-http` crate, while product-facing
//! Swift, Kotlin, Android, TypeScript, FFI, JNI, and WASM layers remain owned
//! by `reallyme/identity`.

mod apply_lifecycle_event;
mod authorize_audit_record;
mod backend;
mod encode_operation_replay;
mod error;
mod execute_operation;
mod handle;
#[cfg(test)]
mod handle_tests;
mod require_active_credential;
mod validate_replay;

pub use backend::{
    FlowSnapshotWriteResult, VersionedCredentialRecord, VersionedFlowSnapshot,
    VersionedWalletLifecycleRecord, WalletRuntimeBackend,
};
pub use error::{
    map_runtime_detail_reason, map_runtime_error_reason, runtime_error_envelope,
    runtime_error_to_proto, wallet_error_envelope, RuntimeError, RuntimeErrorReason, RuntimeResult,
};
pub use execute_operation::WalletOperationExecutor;
pub use handle::WalletCoreRuntime;
pub use reallyme_wallet_storage::{
    OperationIdempotencyKey, OperationReplayDecision, OperationRequestDigest, OperationReservation,
    PresentationCopyClaimPolicy, OPERATION_IDEMPOTENCY_KEY_LENGTH,
};
pub use reallyme_wallet_types::RecordRevision;
