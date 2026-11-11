// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted storage policy for prepared ZK inputs and exact-request outputs.

use crypto_sha2_256::digest;
use reallyme_wallet_types::{
    CredentialRecordId, EncryptedRecord, EncryptedRecordHeader, StorageEncryptionAlgorithm,
    UnixTimestamp,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    proofs::ZkSessionBinding,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, ErrorReason, Result};

const ARTIFACT_ID_BYTES: usize = 32;
const SCOPE_DIGEST_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
const MAX_LINKED_CREDENTIALS: usize = 2;
const REQUEST_ARTIFACT_MAX_LIFETIME_SECONDS: i64 = 300;
/// Prepared inputs and public proofs are reused across sessions but must be
/// re-derived at least once a year rather than stored indefinitely.
const PREPARED_ARTIFACT_MAX_LIFETIME_SECONDS: i64 = 366 * 24 * 60 * 60;
const AAD_DOMAIN: &[u8] = b"reallyme-wallet-zk-artifact-v2\0";

/// Whether an encrypted artifact can be reused for another verifier request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkArtifactKind {
    /// Validated private source material that contains no presentation session.
    PreparedInput,
    /// A witness for one exact verifier request and circuit ABI.
    Witness,
    /// A proof for one exact verifier request and circuit ABI.
    Proof,
    /// A reusable public-persona proof, bound to its public proof window.
    ///
    /// This storage class does not authenticate decrypted proof bytes. Before
    /// disclosure, the presenter must verify the package's public profile,
    /// circuit stage, credential join, proof window, and current issuer status.
    PreparedPublicProof,
}

impl ZkArtifactKind {
    const fn code(self) -> u8 {
        match self {
            Self::PreparedInput => 1,
            Self::Witness => 2,
            Self::Proof => 3,
            Self::PreparedPublicProof => 4,
        }
    }
}

/// Validated, request-aware metadata for one encrypted ZK artifact.
///
/// The credential ids and scope digest are part of authenticated storage AAD.
/// A caller must still revalidate decrypted prepared input against the issuer
/// receipt, or a decrypted witness/proof against the exact ZK circuit contract.
pub struct ZkArtifactDescriptor {
    artifact_id: [u8; ARTIFACT_ID_BYTES],
    credential_ids: Vec<CredentialRecordId>,
    circuit_ref: ZkCircuitRef,
    kind: ZkArtifactKind,
    claim_scope_digest: [u8; SCOPE_DIGEST_BYTES],
    request_binding: Option<ZkSessionBinding>,
    expires_at: UnixTimestamp,
}

impl Drop for ZkArtifactDescriptor {
    fn drop(&mut self) {
        self.artifact_id.zeroize();
        self.claim_scope_digest.zeroize();
        if let Some(binding) = &mut self.request_binding {
            binding.nonce_hash.zeroize();
            binding.audience_hash.zeroize();
            if let Some(transaction_hash) = &mut binding.transaction_data_hash {
                transaction_hash.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for ZkArtifactDescriptor {}

impl ZkArtifactDescriptor {
    /// Admit a source-circuit artifact with explicit credential and request scope.
    pub fn new(
        artifact_id: [u8; ARTIFACT_ID_BYTES],
        credential_ids: Vec<CredentialRecordId>,
        circuit_ref: ZkCircuitRef,
        kind: ZkArtifactKind,
        claim_scope_digest: [u8; SCOPE_DIGEST_BYTES],
        request_binding: Option<ZkSessionBinding>,
        expires_at: UnixTimestamp,
    ) -> Result<Self> {
        if artifact_id == [0; ARTIFACT_ID_BYTES]
            || credential_ids.is_empty()
            || credential_ids.len() > MAX_LINKED_CREDENTIALS
            || (credential_ids.len() == 2 && credential_ids[0] == credential_ids[1])
        {
            return Err(Error::new(ErrorReason::InvalidArtifactIdentity));
        }
        if !ZkCircuitRef::ALL.contains(&circuit_ref)
            || circuit_ref.stage == ZkCircuitStage::ClaimBundle4
        {
            return Err(Error::new(ErrorReason::UnsupportedCircuit));
        }
        if claim_scope_digest == [0; SCOPE_DIGEST_BYTES] {
            return Err(Error::new(ErrorReason::InvalidArtifactScope));
        }
        if kind == ZkArtifactKind::PreparedPublicProof && credential_ids.len() != 1 {
            return Err(Error::new(ErrorReason::InvalidArtifactIdentity));
        }
        if kind == ZkArtifactKind::PreparedPublicProof
            && (circuit_ref.family != ZkCircuitFamily::PersonaCredentialEvidenceV1
                || !matches!(
                    circuit_ref.stage,
                    ZkCircuitStage::EvidenceIssuerEnvelope
                        | ZkCircuitStage::EvidenceClaimRoot
                        | ZkCircuitStage::EvidenceSignedValidity
                        | ZkCircuitStage::EvidencePublicClaim
                        | ZkCircuitStage::EvidenceCurrentState
                ))
        {
            return Err(Error::new(ErrorReason::UnsupportedCircuit));
        }
        if matches!(kind, ZkArtifactKind::Witness | ZkArtifactKind::Proof)
            && circuit_ref.family == ZkCircuitFamily::PersonaCredentialEvidenceV1
        {
            return Err(Error::new(ErrorReason::UnsupportedCircuit));
        }
        match (kind, request_binding) {
            (ZkArtifactKind::PreparedInput, None) => {}
            (ZkArtifactKind::PreparedPublicProof, None) => {}
            (ZkArtifactKind::Witness | ZkArtifactKind::Proof, Some(binding)) => {
                binding
                    .validate_for_circuit(circuit_ref)
                    .map_err(|_| Error::new(ErrorReason::ArtifactBindingMismatch))?;
            }
            _ => return Err(Error::new(ErrorReason::InvalidArtifactScope)),
        }
        Ok(Self {
            artifact_id,
            credential_ids,
            circuit_ref,
            kind,
            claim_scope_digest,
            request_binding,
            expires_at,
        })
    }

    /// Return the exact source circuit selected at artifact creation.
    #[must_use]
    pub const fn circuit_ref(&self) -> ZkCircuitRef {
        self.circuit_ref
    }

    /// Return the opaque artifact key.
    #[must_use]
    pub const fn artifact_id(&self) -> &[u8; ARTIFACT_ID_BYTES] {
        &self.artifact_id
    }

    /// Return the storage treatment required by this artifact.
    #[must_use]
    pub const fn kind(&self) -> ZkArtifactKind {
        self.kind
    }

    /// Return the credential records whose lifecycle controls this artifact.
    #[must_use]
    pub fn credential_ids(&self) -> &[CredentialRecordId] {
        &self.credential_ids
    }

    /// Return the digest of the credential claims selected for this artifact.
    #[must_use]
    pub const fn claim_scope_digest(&self) -> &[u8; SCOPE_DIGEST_BYTES] {
        &self.claim_scope_digest
    }

    /// Return the active verifier binding, when this is a witness or proof.
    #[must_use]
    pub const fn request_binding(&self) -> Option<ZkSessionBinding> {
        self.request_binding
    }

    /// Return the trusted retention deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Return the AEAD associated-data digest of the complete storage header.
    ///
    /// Length prefixes keep distinct identifier sequences from sharing one
    /// transcript. The storage adapter must pass these 32 bytes into its AEAD.
    pub fn aad_digest(&self, header: &EncryptedRecordHeader) -> Result<[u8; 32]> {
        // `v2` versions this transcript, which binds the circuit revision so
        // ciphertext for one revision never authenticates as another.
        let coordinate = format!(
            "{}:{}:{}:v2:r{}",
            self.circuit_ref.credential_hash_algorithm.as_str(),
            self.circuit_ref.family.as_str(),
            self.circuit_ref.stage.as_str(),
            self.circuit_ref.revision
        );
        let key_id = header.key_handle_id.as_str();
        let mut capacity = AAD_DOMAIN
            .len()
            .checked_add(ARTIFACT_ID_BYTES + SCOPE_DIGEST_BYTES + 2 + 1 + 8 + 8 + 1 + 1)
            .ok_or(Error::new(ErrorReason::InvalidArtifactEncoding))?;
        for value in [coordinate.as_str(), key_id] {
            capacity = capacity
                .checked_add(2)
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(Error::new(ErrorReason::InvalidArtifactEncoding))?;
        }
        for credential_id in &self.credential_ids {
            capacity = capacity
                .checked_add(2)
                .and_then(|size| size.checked_add(credential_id.as_str().len()))
                .ok_or(Error::new(ErrorReason::InvalidArtifactEncoding))?;
        }
        if self.request_binding.is_some() {
            capacity = capacity
                .checked_add(32 + 32 + 1 + 32)
                .ok_or(Error::new(ErrorReason::InvalidArtifactEncoding))?;
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        bytes.extend_from_slice(AAD_DOMAIN);
        bytes.extend_from_slice(&self.artifact_id);
        bytes.push(
            u8::try_from(self.credential_ids.len())
                .map_err(|_| Error::new(ErrorReason::InvalidArtifactEncoding))?,
        );
        for credential_id in &self.credential_ids {
            append_bounded_text(&mut bytes, credential_id.as_str())?;
        }
        append_bounded_text(&mut bytes, &coordinate)?;
        bytes.push(self.kind.code());
        bytes.extend_from_slice(&self.claim_scope_digest);
        match self.request_binding {
            Some(binding) => {
                bytes.push(1);
                bytes.extend_from_slice(&binding.nonce_hash);
                bytes.extend_from_slice(&binding.audience_hash);
                match binding.transaction_data_hash {
                    Some(hash) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&hash);
                    }
                    None => bytes.push(0),
                }
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.expires_at.as_seconds().to_be_bytes());
        bytes.extend_from_slice(&header.schema_version.to_be_bytes());
        append_bounded_text(&mut bytes, key_id)?;
        bytes.push(match header.algorithm {
            StorageEncryptionAlgorithm::Aes256GcmSiv => 1,
            StorageEncryptionAlgorithm::XChaCha20Poly1305 => 2,
        });
        bytes.extend_from_slice(&header.created_at.as_seconds().to_be_bytes());
        Ok(digest(&bytes).into_bytes())
    }

    /// Enforce expiry and, for request-bound material, the active request.
    ///
    /// Stored material goes through `ZkStoredArtifactRecord::validate_use`,
    /// which also refuses a creation time after trusted `now`.
    pub(crate) fn validate_use(
        &self,
        now: UnixTimestamp,
        request_binding: Option<ZkSessionBinding>,
    ) -> Result<()> {
        if now >= self.expires_at {
            return Err(Error::new(ErrorReason::ArtifactExpired));
        }
        match (self.request_binding, request_binding) {
            // Prepared openings have no verifier-session dependency. A caller
            // may still be processing an active request when it retrieves one.
            (None, _) => Ok(()),
            (Some(stored), Some(active)) if binding_matches(stored, active) => Ok(()),
            _ => Err(Error::new(ErrorReason::ArtifactBindingMismatch)),
        }
    }
}

/// Encrypted payload plus metadata that must be checked before decryption.
pub struct ZkStoredArtifactRecord {
    descriptor: ZkArtifactDescriptor,
    encrypted: EncryptedRecord,
}

impl ZeroizeOnDrop for ZkStoredArtifactRecord {}

impl ZkStoredArtifactRecord {
    /// Admit ciphertext only when AEAD routing metadata matches the descriptor.
    pub fn new(descriptor: ZkArtifactDescriptor, encrypted: EncryptedRecord) -> Result<Self> {
        if encrypted.header.schema_version == 0
            || encrypted.nonce.len() != encrypted.header.algorithm.nonce_length()
            || encrypted.ciphertext.len() < AEAD_TAG_BYTES
        {
            return Err(Error::new(ErrorReason::InvalidArtifactEncoding));
        }
        if descriptor.expires_at <= encrypted.header.created_at {
            return Err(Error::new(ErrorReason::ArtifactExpired));
        }
        let lifetime = descriptor
            .expires_at
            .as_seconds()
            .checked_sub(encrypted.header.created_at.as_seconds())
            .ok_or(Error::new(ErrorReason::InvalidArtifactScope))?;
        let max_lifetime = match descriptor.kind {
            ZkArtifactKind::PreparedInput | ZkArtifactKind::PreparedPublicProof => {
                PREPARED_ARTIFACT_MAX_LIFETIME_SECONDS
            }
            ZkArtifactKind::Witness | ZkArtifactKind::Proof => {
                REQUEST_ARTIFACT_MAX_LIFETIME_SECONDS
            }
        };
        if lifetime > max_lifetime {
            return Err(Error::new(ErrorReason::InvalidArtifactScope));
        }
        let expected_aad = descriptor.aad_digest(&encrypted.header)?;
        if encrypted.aad.len() != expected_aad.len()
            || !bool::from(encrypted.aad.as_slice().ct_eq(&expected_aad))
        {
            return Err(Error::new(ErrorReason::ArtifactBindingMismatch));
        }
        Ok(Self {
            descriptor,
            encrypted,
        })
    }

    /// Enforce creation time, expiry, and request binding before decryption.
    ///
    /// A record dated after trusted `now` is refused, so a future
    /// `created_at` cannot stretch the lifetime bound measured from it.
    pub fn validate_use(
        &self,
        now: UnixTimestamp,
        request_binding: Option<ZkSessionBinding>,
    ) -> Result<()> {
        if self.encrypted.header.created_at > now {
            return Err(Error::new(ErrorReason::InvalidArtifactScope));
        }
        self.descriptor.validate_use(now, request_binding)
    }

    /// Borrow the validated metadata to select the exact circuit and lifecycle.
    #[must_use]
    pub const fn descriptor(&self) -> &ZkArtifactDescriptor {
        &self.descriptor
    }

    /// Borrow ciphertext for the configured platform storage implementation.
    #[must_use]
    pub const fn encrypted(&self) -> &EncryptedRecord {
        &self.encrypted
    }
}

fn append_bounded_text(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    let length =
        u16::try_from(value.len()).map_err(|_| Error::new(ErrorReason::InvalidArtifactEncoding))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(crate) fn binding_matches(stored: ZkSessionBinding, active: ZkSessionBinding) -> bool {
    bool::from(stored.nonce_hash.ct_eq(&active.nonce_hash))
        && bool::from(stored.audience_hash.ct_eq(&active.audience_hash))
        && match (stored.transaction_data_hash, active.transaction_data_hash) {
            (None, None) => true,
            (Some(left), Some(right)) => bool::from(left.ct_eq(&right)),
            _ => false,
        }
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;
