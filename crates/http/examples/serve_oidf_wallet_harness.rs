// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serve the OIDF conformance wallet harness over HTTP.
//!
//! This executable is intentionally small: it binds a local HTTP listener and
//! serves the framework adapter from `reallyme-wallet-http`. It is a
//! transport smoke harness only. A passing OIDF wallet run needs an identity
//! or app-composed binary that injects `OidfWalletFlowDriver`.

use std::env;
use std::net::SocketAddr;

use reallyme_wallet_http::{oidf_wallet_harness_router, OidfWalletHarnessState};
use thiserror::Error;
use zeroize::Zeroizing;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:8787";

#[derive(Debug, Error)]
enum HarnessServeError {
    #[error("invalid_bind_address")]
    InvalidBindAddress,
    #[error("unexpected_argument")]
    UnexpectedArgument,
    #[error("bind_failed")]
    BindFailed,
    #[error("serve_failed")]
    ServeFailed,
    #[error("invalid_host_configuration")]
    InvalidHostConfiguration,
    #[error("invalid_control_token")]
    InvalidControlToken,
    #[error("invalid_callback_origins")]
    InvalidCallbackOrigins,
}

#[tokio::main]
async fn main() -> Result<(), HarnessServeError> {
    let bind = bind_address()?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| HarnessServeError::BindFailed)?;
    let bind_host = bind.to_string();
    let mut state = OidfWalletHarnessState::new()
        .with_allowed_hosts(&[bind_host.as_str()])
        .map_err(|_| HarnessServeError::InvalidHostConfiguration)?;
    match env::var("OIDF_WALLET_HARNESS_CONTROL_TOKEN") {
        Ok(token) => {
            state = state
                .with_control_token(Zeroizing::new(token))
                .map_err(|_| HarnessServeError::InvalidControlToken)?;
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => return Err(HarnessServeError::InvalidControlToken),
    }
    // Comma-separated HTTPS origins the suite's verifier uses for
    // `request_uri`, `response_uri`, and `redirect_uri`. Without them every
    // launch that names a callback is refused as `invalid_request`.
    match env::var("OIDF_WALLET_HARNESS_CALLBACK_ORIGINS") {
        Ok(origins) => {
            let origins: Vec<&str> = origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .collect();
            state = state
                .with_allowed_callback_origins(&origins)
                .map_err(|_| HarnessServeError::InvalidCallbackOrigins)?;
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => {
            return Err(HarnessServeError::InvalidCallbackOrigins);
        }
    }
    let app = oidf_wallet_harness_router(state);

    axum::serve(listener, app)
        .await
        .map_err(|_| HarnessServeError::ServeFailed)
}

fn bind_address() -> Result<SocketAddr, HarnessServeError> {
    let mut args = env::args();
    let _binary = args.next();
    let raw = match args.next() {
        Some(value) => value,
        None => DEFAULT_BIND_ADDRESS.to_owned(),
    };
    if args.next().is_some() {
        return Err(HarnessServeError::UnexpectedArgument);
    }

    let address: SocketAddr = raw
        .parse()
        .map_err(|_| HarnessServeError::InvalidBindAddress)?;
    if !address.ip().is_loopback() {
        return Err(HarnessServeError::InvalidBindAddress);
    }
    Ok(address)
}
