// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Presentation derivation through an injected ZK proving backend.

use std::sync::Arc;

use reallyme_zk_api::proofs::ZkProofSuite;
use reallyme_zk_api::proofs::{ZkProof, ZkProveRequest, ZkProver, ZkSessionBinding};

use crate::artifact::binding_matches;

use crate::{Error, ErrorReason, Result};

/// Injected dependencies for optional ZK presentation derivation.
#[derive(Clone, Default)]
pub struct PresentationDerivationContext {
    prover: Option<Arc<dyn ZkProver>>,
}

impl PresentationDerivationContext {
    /// Create a context without a ZK prover.
    #[must_use]
    pub const fn without_prover() -> Self {
        Self { prover: None }
    }

    /// Create a context with an application-provided ZK prover.
    #[must_use]
    pub fn with_prover(prover: Arc<dyn ZkProver>) -> Self {
        Self {
            prover: Some(prover),
        }
    }

    /// Borrow the injected prover when one is available.
    #[must_use]
    pub fn prover(&self) -> Option<&dyn ZkProver> {
        self.prover.as_deref()
    }
}

/// Produce a ZK presentation derivation through the injected prover.
///
/// This integration crate never constructs a concrete proving backend. The
/// application injects the selected implementation, and absence fails closed.
///
/// `active_session` is the binding derived from the verified OpenID4VP request
/// being answered now: its nonce, audience, and transaction data hashes. The
/// request's own binding must equal it, so a witness or public inputs prepared
/// for an earlier verifier session cannot be proved into this response.
pub fn prove_presentation_derivation(
    context: &PresentationDerivationContext,
    request: ZkProveRequest<'_>,
    active_session: ZkSessionBinding,
) -> Result<ZkProof> {
    if !binding_matches(request.session_binding(), active_session) {
        return Err(Error::new(ErrorReason::SessionBindingInvalid));
    }
    // Only the approved production suite may back a disclosure. Compatibility
    // suites are not approved for it, and the unmasked ones do not hide the
    // witness, so a presentation built with them could reveal private claims.
    if request.proof_suite() != ZkProofSuite::PRODUCTION {
        return Err(Error::new(ErrorReason::UnsupportedProofSuite));
    }
    let circuit_ref = request.circuit_ref();
    if circuit_ref.circuit_id() != request.circuit_id() {
        return Err(Error::new(ErrorReason::SessionBindingInvalid));
    }
    request
        .session_binding()
        .decode_and_validate(circuit_ref, request.public_inputs())
        .map_err(|_| Error::new(ErrorReason::SessionBindingInvalid))?;
    let prover = context
        .prover()
        .ok_or(Error::new(ErrorReason::ProverUnavailable))?;

    let proof = prover
        .prove(request)
        .map_err(|_| Error::new(ErrorReason::ProofFailed))?;
    if proof.circuit_id() != request.circuit_id()
        || proof.circuit_ref() != circuit_ref
        || proof.proof_suite() != request.proof_suite()
        || proof.public_inputs().as_bytes() != request.public_inputs().as_bytes()
    {
        return Err(Error::new(ErrorReason::ProofMetadataMismatch));
    }
    request
        .session_binding()
        .decode_and_validate(proof.circuit_ref(), proof.public_inputs())
        .map_err(|_| Error::new(ErrorReason::SessionBindingInvalid))?;
    Ok(proof)
}

#[cfg(test)]
#[path = "prove_presentation_derivation_tests.rs"]
mod tests;
