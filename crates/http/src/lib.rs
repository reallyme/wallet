// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native HTTP adapters for the canonical Wallet protobuf runtime.
//!
//! Framework concerns live here so `reallyme-wallet-runtime` remains a
//! transport-neutral operation dispatcher. Platform SDK bindings and final
//! application servers remain owned by `reallyme/identity`.

#[cfg(all(target_arch = "wasm32", feature = "native"))]
compile_error!(
    "reallyme-wallet-http is native-only and cannot enable its native feature on wasm32"
);

#[cfg(not(target_arch = "wasm32"))]
mod serve;
#[cfg(all(not(target_arch = "wasm32"), feature = "oidf-conformance-harness"))]
mod serve_oidf_wallet_harness;
#[cfg(not(target_arch = "wasm32"))]
pub use serve::{
    default_max_body_bytes, wallet_router, AxumWalletError, AxumWalletState,
    WalletHttpRequestAuthorizer,
};
#[cfg(all(not(target_arch = "wasm32"), feature = "oidf-conformance-harness"))]
pub use serve_oidf_wallet_harness::{
    oidf_wallet_harness_router, OidfBrowserApiProtocol, OidfBrowserApiProtocolRequest,
    OidfBrowserApiRequest, OidfBrowserHandoff, OidfWalletFlowDriver, OidfWalletFlowError,
    OidfWalletFlowErrorReason, OidfWalletFlowOutcome, OidfWalletFlowRequest, OidfWalletFlowStatus,
    OidfWalletHarnessError, OidfWalletHarnessState, MAX_OIDF_BROWSER_HANDOFF_URI_BYTES,
};
