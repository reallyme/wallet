// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider policy consumed by SDK-owned Wallet adapters.
//!
//! This crate validates generated provider protobuf messages without owning a
//! platform callback ABI or persistence implementation.

mod allocate_request_id;
mod backend;
mod error;
mod host_capability_error;
mod key_storage;
mod provide_trusted_time;
mod provider_backend;
mod provider_call_support;
mod reconcile_lifecycle_retry;
mod track_claimed_copies;
mod transport;
mod validate_descriptor;
mod validate_response;
mod verify_lifecycle_authority;

pub use allocate_request_id::{ProviderExecutorId, ProviderRequestSequence};
pub use error::{ProviderContractError, ProviderContractErrorReason, ProviderContractResult};
pub use host_capability_error::{ProviderHostCapabilityError, ProviderHostCapabilityErrorReason};
pub use key_storage::VersionedKeyStorageRecord;
pub use provide_trusted_time::ProviderTrustedClock;
pub use provider_backend::{
    AsynchronousHostProtobufProviderBackend, SynchronousProtobufProviderBackend,
};
pub use transport::{
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult,
};
pub use validate_descriptor::{
    build_provider_descriptor, validate_provider_descriptor, ProviderInvocationMode,
    ValidatedProviderDescriptor, REQUIRED_PROVIDER_CAPABILITIES, WALLET_PROVIDER_CONTRACT_VERSION,
};
pub use validate_response::{validate_provider_exchange, ProviderMethod, ValidatedProviderOutcome};
pub use verify_lifecycle_authority::WalletLifecycleAuthorityVerifier;
