// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional wallet rendering and distribution boundary.
//!
//! Renders Apple Wallet passes and Google Wallet JWTs and builds bounded
//! QR-safe text and deep links. The Wallet facade exposes this crate through
//! its optional `render` feature. PDF and QR image rendering are not implemented.

mod apple;
mod build_google_wallet_jwt;
mod error;
mod google;
mod render;
mod web;

pub use apple::{PassSigner, PkPassConfig, PkPassRenderer};
pub use build_google_wallet_jwt::GoogleWalletJwtConfig;
pub use error::{RenderError, RenderErrorReason, RenderResult};
pub use google::{
    build_google_wallet_save_link, GoogleWalletClock, GoogleWalletConfig, GoogleWalletRenderer,
    GoogleWalletSaveConfig, GoogleWalletSaveLink, GoogleWalletSigner,
};
pub use render::WalletRenderer;
pub use web::{
    build_web_deep_link, build_web_qr, WebDeepLink, WebDeliveryEnvelope, WebDeliveryLimits,
    WebDeliveryPayload, WebLinkParam, WebQrPayload,
};
