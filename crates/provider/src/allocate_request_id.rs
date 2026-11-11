// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Allocate checked request identifiers within one provider executor.

use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;

use crate::{
    validate_response::ProviderMethod, ProviderContractError, ProviderContractErrorReason,
    ProviderContractResult, WALLET_PROVIDER_CONTRACT_VERSION,
};

/// Non-zero adapter-assigned identifier for one executor handle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderExecutorId(u64);

impl ProviderExecutorId {
    /// Validate an adapter-assigned executor identifier.
    pub fn new(value: u64) -> ProviderContractResult<Self> {
        if value == 0 {
            return Err(ProviderContractError::new(
                ProviderContractErrorReason::ExecutorIdInvalid,
            ));
        }
        Ok(Self(value))
    }

    /// Return the identifier for provider request correlation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Monotonic checked request-id allocator scoped to one executor.
pub struct ProviderRequestSequence {
    executor_id: ProviderExecutorId,
    next_request_id: u64,
}

impl ProviderRequestSequence {
    /// Start request correlation for an executor handle.
    #[must_use]
    pub const fn new(executor_id: ProviderExecutorId) -> Self {
        Self {
            executor_id,
            next_request_id: 1,
        }
    }

    /// Assign version and correlation fields to a provider request.
    pub fn assign(
        &mut self,
        request: &mut pb::WalletProviderRequest,
    ) -> ProviderContractResult<()> {
        ProviderMethod::from_request(request)?;
        let request_id = self.take_next()?;
        request.contract_version = WALLET_PROVIDER_CONTRACT_VERSION;
        request.executor_id = self.executor_id.value();
        request.request_id = request_id;
        Ok(())
    }

    // Keep overflow handling explicit for the audit-facing request sequence;
    // the workspace intentionally avoids unwrap-family helpers in production.
    #[allow(clippy::manual_unwrap_or, clippy::manual_unwrap_or_default)]
    fn take_next(&mut self) -> ProviderContractResult<u64> {
        if self.next_request_id == 0 {
            return Err(ProviderContractError::new(
                ProviderContractErrorReason::RequestIdExhausted,
            ));
        }
        let current = self.next_request_id;
        self.next_request_id = match current.checked_add(1) {
            Some(next) => next,
            None => 0,
        };
        Ok(current)
    }
}

#[cfg(test)]
#[path = "allocate_request_id_tests.rs"]
mod tests;
