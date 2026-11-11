// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Derive the consent binding from a verified OpenID4VP Authorization Request.
//!
//! Consent is claimed once per relying party and verifier nonce, and the
//! captured decision is tied to a digest of the exact verified request. Both
//! values are derived here from the verification receipt so a caller cannot
//! substitute a fresh nonce or an unrelated digest for a request it already
//! obtained consent for.

use core::fmt::Write;

use reallyme_codec::jcs::canonicalize_json_text;
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientIdentifierPrefix,
};
use reallyme_wallet_types::{NonEmptyIdentifier, RelyingPartyId, CONSENT_REQUEST_DIGEST_BYTES};
use zeroize::Zeroizing;

use crate::{ConsentError, ConsentErrorReason, ConsentResult};

/// Domain separator for the consent request transcript digest.
pub(crate) const CONSENT_REQUEST_TRANSCRIPT_DOMAIN: &[u8] =
    b"reallyme-wallet/v1/consent-request-transcript\0";

/// Domain separator for the client-identifier digest that scopes consent claims.
pub(crate) const CONSENT_CLAIM_SCOPE_DOMAIN: &[u8] = b"reallyme-wallet/v1/consent-claim-scope\0";

/// Prefix of the claim-scope identifier passed to the consent store.
const CONSENT_CLAIM_SCOPE_PREFIX: &str = "client-sha256:";

/// Upper bound on the canonical request transcript hashed for consent.
///
/// The protocol layer bounds verified Request Objects well below this value;
/// the limit is a second guard before allocating the transcript buffer.
pub(crate) const MAX_CONSENT_REQUEST_TRANSCRIPT_BYTES: usize = 1_048_576;

/// Verifier-bound consent coordinates derived from one verified request.
pub(crate) struct VerifiedRequestBinding {
    pub(crate) request_nonce: NonEmptyIdentifier,
    pub(crate) request_digest: [u8; CONSENT_REQUEST_DIGEST_BYTES],
}

/// Derive the verifier nonce and canonical request digest used for consent.
///
/// The digest covers the RFC 8785 canonical JSON form of every parameter the
/// protocol crate models on the verified Authorization Request Object,
/// including `client_id`, `nonce`, `response_uri`, `state`, `dcql_query`, and
/// `transaction_data`, under a Wallet-specific domain separator. Parameters
/// the protocol crate does not model are not bound.
pub(crate) fn derive_verified_request_binding(
    request: &AuthorizationRequestObject,
) -> ConsentResult<VerifiedRequestBinding> {
    let request_nonce = NonEmptyIdentifier::new(request.nonce.clone())
        .map_err(|_| ConsentError::new(ConsentErrorReason::RequestBindingMismatch))?;
    // Serialize into a writer that stops at the bound, so an oversized
    // request is refused before it is fully materialized.
    let mut writer = BoundedWriter::new(MAX_CONSENT_REQUEST_TRANSCRIPT_BYTES)?;
    if serde_json::to_writer(&mut writer, request).is_err() {
        return Err(ConsentError::new(if writer.exceeded() {
            ConsentErrorReason::ScopeTooLarge
        } else {
            ConsentErrorReason::RequestBindingMismatch
        }));
    }
    let serialized = Zeroizing::new(
        String::from_utf8(core::mem::take(&mut *writer.bytes))
            .map_err(|_| ConsentError::new(ConsentErrorReason::RequestBindingMismatch))?,
    );
    let canonical = Zeroizing::new(
        canonicalize_json_text(&serialized)
            .map_err(|_| ConsentError::new(ConsentErrorReason::RequestBindingMismatch))?,
    );
    let transcript_len = CONSENT_REQUEST_TRANSCRIPT_DOMAIN
        .len()
        .checked_add(canonical.len())
        .filter(|length| *length <= MAX_CONSENT_REQUEST_TRANSCRIPT_BYTES)
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
    let mut transcript = Zeroizing::new(Vec::with_capacity(transcript_len));
    transcript.extend_from_slice(CONSENT_REQUEST_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(canonical.as_bytes());
    let request_digest = crypto_sha2_256::digest(transcript.as_slice()).into_bytes();
    Ok(VerifiedRequestBinding {
        request_nonce,
        request_digest,
    })
}

/// Byte sink that refuses to grow past `limit`.
struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedWriter {
    /// Reserve the whole bound once, so writes never reallocate and leave an
    /// unwiped copy of the request behind.
    fn new(limit: usize) -> ConsentResult<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
        Ok(Self { bytes, limit })
    }

    fn exceeded(&self) -> bool {
        self.bytes.len() >= self.limit
    }
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(data.len())
            .filter(|length| *length <= self.limit)
            .ok_or_else(|| std::io::Error::other("transcript bound"))?;
        if next > self.bytes.capacity() {
            return Err(std::io::Error::other("transcript capacity"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Derive the store key that scopes a consent claim to one verifier.
///
/// The key comes from the verified request's `client_id`, not from the
/// entitlement's relying-party string, so two entitlements that spell the same
/// verifier differently still share one nonce namespace. DNS names are
/// compared without case. The digest keeps the key inside identifier bounds
/// for any client identifier length.
pub(crate) fn derive_consent_claim_scope(
    client_id: &ClientIdentifier,
) -> ConsentResult<RelyingPartyId> {
    let mut canonical = Zeroizing::new(client_id.to_wire_value());
    if client_id.prefix() == ClientIdentifierPrefix::X509SanDns {
        canonical.make_ascii_lowercase();
    }
    let mut input = Zeroizing::new(Vec::with_capacity(
        CONSENT_CLAIM_SCOPE_DOMAIN
            .len()
            .checked_add(canonical.len())
            .ok_or_else(|| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?,
    ));
    input.extend_from_slice(CONSENT_CLAIM_SCOPE_DOMAIN);
    input.extend_from_slice(canonical.as_bytes());
    let digest = crypto_sha2_256::digest(input.as_slice()).into_bytes();
    let mut scope = String::with_capacity(
        digest
            .len()
            .checked_mul(2)
            .and_then(|hex| hex.checked_add(CONSENT_CLAIM_SCOPE_PREFIX.len()))
            .ok_or_else(|| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?,
    );
    scope.push_str(CONSENT_CLAIM_SCOPE_PREFIX);
    for byte in digest {
        write!(scope, "{byte:02x}")
            .map_err(|_| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))?;
    }
    NonEmptyIdentifier::new(scope)
        .map_err(|_| ConsentError::new(ConsentErrorReason::ClientBindingMismatch))
}

#[cfg(test)]
#[path = "bind_verified_request_tests.rs"]
mod tests;
