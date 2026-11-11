// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet unit attestation records.

use reallyme_wallet_keystore::{KeyAttestationEvidence, MAX_KEY_ATTESTATION_EVIDENCE_BYTES};
use reallyme_wallet_types::{UnixTimestamp, WalletUnitAttestationId};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{AttestationError, AttestationErrorReason, AttestationResult};

const MAX_SIGNED_WALLET_UNIT_ATTESTATION_BYTES: usize = 65_536;

/// Key identity extracted while verifying the provider-signed attestation.
///
/// The verifier must derive this thumbprint from authenticated public key
/// material, rather than a caller-provided key-handle name.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct VerifiedWalletKeyThumbprint([u8; 32]);

impl VerifiedWalletKeyThumbprint {
    /// Accept a canonical SHA-256 thumbprint returned by the trust verifier.
    pub fn new(bytes: [u8; 32]) -> AttestationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(AttestationError::new(
                AttestationErrorReason::InvalidAttestationEvidence,
            ));
        }
        Ok(Self(bytes))
    }

    /// Borrow the canonical digest for a checked keystore/WUA comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Provider response that has not yet crossed the cryptographic trust boundary.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct UnverifiedWalletUnitAttestation {
    id: WalletUnitAttestationId,
    evidence: KeyAttestationEvidence,
    valid_until: UnixTimestamp,
    signed_provider_artifact: Vec<u8>,
}

impl UnverifiedWalletUnitAttestation {
    /// Construct a bounded provider response for cryptographic verification.
    pub fn new(
        id: WalletUnitAttestationId,
        evidence: KeyAttestationEvidence,
        valid_until: UnixTimestamp,
        signed_provider_artifact: Vec<u8>,
    ) -> AttestationResult<Self> {
        // Keep ownership of rejected provider bytes under a wiping guard.
        let mut signed_provider_artifact = Zeroizing::new(signed_provider_artifact);
        if evidence.evidence.is_empty()
            || evidence.evidence.len() > MAX_KEY_ATTESTATION_EVIDENCE_BYTES
            || evidence.challenge.iter().all(|byte| *byte == 0)
            || signed_provider_artifact.is_empty()
            || signed_provider_artifact.len() > MAX_SIGNED_WALLET_UNIT_ATTESTATION_BYTES
        {
            return Err(AttestationError::new(
                AttestationErrorReason::InvalidAttestationEvidence,
            ));
        }
        Ok(Self {
            id,
            evidence,
            valid_until,
            signed_provider_artifact: std::mem::take(&mut *signed_provider_artifact),
        })
    }

    /// Borrow the provider-assigned attestation identifier.
    #[must_use]
    pub const fn id(&self) -> &WalletUnitAttestationId {
        &self.id
    }

    /// Borrow the key evidence covered by the signed provider artifact.
    #[must_use]
    pub const fn evidence(&self) -> &KeyAttestationEvidence {
        &self.evidence
    }

    /// Return the signed validity limit.
    #[must_use]
    pub const fn valid_until(&self) -> UnixTimestamp {
        self.valid_until
    }

    /// Borrow the opaque provider-signed attestation artifact.
    #[must_use]
    pub fn signed_provider_artifact(&self) -> &[u8] {
        &self.signed_provider_artifact
    }
}

/// Wallet unit attestation presented during issuance.
///
/// Cloning supports transactional issuance-session snapshots. Each copy owns
/// and wipes its identifier and attestation evidence independently.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WalletUnitAttestation {
    /// Stable attestation id.
    id: WalletUnitAttestationId,
    /// Provider-issued attestation evidence.
    evidence: KeyAttestationEvidence,
    /// Expiry time.
    valid_until: UnixTimestamp,
    /// Provider-signed bytes verified together with every typed field.
    signed_provider_artifact: Vec<u8>,
    /// Verified public-key identity retained only in memory; restore verifies
    /// the signed provider artifact again to reconstruct this value.
    verified_key_thumbprint: VerifiedWalletKeyThumbprint,
}

impl WalletUnitAttestation {
    pub(crate) fn from_verified(
        unverified: UnverifiedWalletUnitAttestation,
        verified_key_thumbprint: VerifiedWalletKeyThumbprint,
    ) -> Self {
        Self {
            id: unverified.id.clone(),
            evidence: unverified.evidence.clone(),
            valid_until: unverified.valid_until,
            signed_provider_artifact: unverified.signed_provider_artifact.clone(),
            verified_key_thumbprint,
        }
    }

    /// Borrow the provider-assigned attestation identifier.
    #[must_use]
    pub const fn id(&self) -> &WalletUnitAttestationId {
        &self.id
    }

    /// Borrow the verified key-attestation evidence.
    #[must_use]
    pub const fn evidence(&self) -> &KeyAttestationEvidence {
        &self.evidence
    }

    /// Return the verified attestation expiry.
    #[must_use]
    pub const fn valid_until(&self) -> UnixTimestamp {
        self.valid_until
    }

    /// Borrow the provider-signed artifact retained for persistence and re-verification.
    #[must_use]
    pub fn signed_provider_artifact(&self) -> &[u8] {
        &self.signed_provider_artifact
    }

    /// Return the authenticated key identity for continuity checks.
    #[must_use]
    pub const fn verified_key_thumbprint(&self) -> &VerifiedWalletKeyThumbprint {
        &self.verified_key_thumbprint
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
