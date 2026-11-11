// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated proof bindings returned by credential-request verification.

use openid4vci_types::CredentialRequest;
use reallyme_wallet_types::{KeyHandleId, UnixTimestamp};

use crate::FlowResult;
use zeroize::ZeroizeOnDrop;

/// Authenticated bindings extracted from a credential request proof.
#[derive(ZeroizeOnDrop)]
pub struct CredentialProofBinding {
    /// Digest of exact nonce bytes authenticated from this signed proof.
    pub nonce_digest: Option<[u8; 32]>,
    /// Proof audience authenticated by the proof verifier.
    pub audience: String,
    /// Opaque credential-binding key handle authenticated by the proof verifier.
    pub holder_key_handle_id: KeyHandleId,
    /// Proof issuance time authenticated by the proof verifier.
    pub issued_at: UnixTimestamp,
}

/// Authenticated bindings extracted from a credential request's ordered proofs.
#[derive(ZeroizeOnDrop)]
pub struct CredentialRequestProofBinding {
    /// One authenticated binding for each proof, preserving request order.
    pub proofs: Vec<CredentialProofBinding>,
    /// Wallet-unit key identity under which the proof verifier authorized the
    /// credential-binding key.
    ///
    /// Keeping this binding explicit lets wallet-core preserve its attestation
    /// invariant while supporting a distinct per-credential proof key.
    pub wallet_unit_key_handle_id: KeyHandleId,
}

/// Injected proof-verification boundary for holder credential requests.
pub trait CredentialRequestProofVerifier {
    /// Verify the request proof and return only authenticated bindings.
    fn verify_credential_request_proof(
        &self,
        request: &CredentialRequest,
    ) -> FlowResult<CredentialRequestProofBinding>;
}
