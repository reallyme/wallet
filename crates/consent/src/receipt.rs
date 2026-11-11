// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticate neutral reader facts and retain the exact policy authorization receipt.

use crate::capture::{prepare_consent_request_from_entitlement, validate_prepared_capture};
use crate::{
    AuthorizedDisclosure, CapturedConsent, ConsentError, ConsentErrorReason, ConsentResult,
    PreparedConsentRequest, TrustedConsentClock, UnregisteredAttributePolicy,
};
use reallyme_openid4vp_wallet::VerifiedWalletRequest;
use reallyme_wallet_storage::{ConsentCaptureStore, ConsentCaptureStoreErrorReason};
use reallyme_wallet_types::{
    ConsentAction, ConsentCapture, ConsentPolicyContext, ConsentReceipt, ConsentRetention,
    ConsentScope, NonEmptyIdentifier, ReaderSessionBinding, RelyingPartyId, UnixTimestamp,
    VerifierEntitlement, MAX_CONSENT_POLICIES,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const CONTEXT_DOMAIN: &[u8] = b"reallyme.wallet.consent-context.v1\0";
const READER_DOMAIN: &[u8] = b"reallyme.wallet.reader-consent.v1\0";
const MAX_POLICY_TRANSCRIPT_BYTES: usize = 32_768;
/// Authenticated facts produced by the host's SSI reader/session verifier.
#[derive(ZeroizeOnDrop)]
pub struct ReaderAuthorizationFacts {
    /// Authenticated reader, transcript, and evidence lifetime.
    pub binding: ReaderSessionBinding,
    /// Reader authority and scope authenticated by the provider.
    pub entitlement: VerifierEntitlement,
    /// Exact claims in the authenticated reader request.
    pub requested_scope: ConsentScope,
    /// Exact nonce authenticated with that request.
    pub request_nonce: NonEmptyIdentifier,
}
/// SSI/Identity implement authentication; Wallet never parses ISO reader messages.
pub trait ReaderAuthorizationVerifier {
    /// Protocol-owner evidence type; the provider enforces pre-crypto decode bounds.
    type Evidence;
    /// Verify reader signature, transcript, trust/status, and requested claims.
    fn verify_reader(
        &self,
        evidence: &Self::Evidence,
        now: UnixTimestamp,
    ) -> ConsentResult<ReaderAuthorizationFacts>;
}
/// Exact policy verification result bound to one RP/request and policy transcript.
#[derive(ZeroizeOnDrop)]
pub struct PolicyContextAuthorization {
    /// Authenticated recipient.
    pub relying_party_id: RelyingPartyId,
    /// Authenticated presentation request.
    pub request_digest: [u8; 32],
    /// Digest computed by `consent_policy_digest` for the supported terms.
    pub policy_digest: [u8; 32],
    /// Verification time.
    pub verified_at: UnixTimestamp,
    /// Exclusive freshness deadline.
    pub valid_until: UnixTimestamp,
}
/// Authenticate policy identities, versions, purpose, retention, and transaction
/// assignment through the SSI policy owner. Unsupported mandatory semantics must
/// return PolicyUnsupported; a transport success is never policy authorization.
pub trait ConsentPolicyVerifier {
    /// Verify the exact context and bind the result to this request and recipient.
    fn verify_policy_context(
        &self,
        request: &reallyme_wallet_types::ConsentRequest,
        context: &ConsentPolicyContext,
        now: UnixTimestamp,
    ) -> ConsentResult<PolicyContextAuthorization>;
}
/// Prepared receipt context; only authenticated preparation creates this capability.
pub struct PreparedReceiptConsent {
    prepared: PreparedConsentRequest,
    policy: Option<ConsentPolicyContext>,
    policy_authorization: Option<PolicyContextAuthorization>,
    reader: Option<ReaderSessionBinding>,
    context_digest: Zeroizing<[u8; 32]>,
}
impl PreparedReceiptConsent {
    /// Request/actions to render to the holder.
    pub const fn request(&self) -> &reallyme_wallet_types::ConsentRequest {
        self.prepared.request()
    }
    /// Exact authenticated policy terms to render, when present.
    pub const fn policy(&self) -> Option<&ConsentPolicyContext> {
        self.policy.as_ref()
    }
    /// Reader/session facts to render or bind to the SSI response.
    pub const fn reader(&self) -> Option<&ReaderSessionBinding> {
        self.reader.as_ref()
    }
    /// Approval must return this exact context digest alongside the capture.
    pub fn context_digest(&self) -> &[u8; 32] {
        &self.context_digest
    }
    /// Requested attributes the relying party or reader did not register.
    ///
    /// Per ARF EW-DM-44-027 (legacy RPRC_21) the host must warn the user
    /// about these when asking for approval, for online and proximity
    /// requests alike, whichever `UnregisteredAttributePolicy` applies. An
    /// empty slice means every requested attribute is registered.
    pub fn unregistered_attributes(&self) -> &[reallyme_wallet_types::AttributeName] {
        self.prepared.unregistered_attributes()
    }
}
/// Authorization after one atomic nonce claim and full receipt append.
pub struct CapturedReceiptConsent {
    valid_until: Zeroizing<UnixTimestamp>,
    consent: CapturedConsent,
    receipt: ConsentReceipt,
    context_digest: Zeroizing<[u8; 32]>,
}
/// Single-use final scope and context authorization; receipt copies convey no capability.
pub struct AuthorizedReceiptDisclosure {
    valid_until: Zeroizing<UnixTimestamp>,
    authorization: AuthorizedDisclosure,
    receipt: ConsentReceipt,
}
impl AuthorizedReceiptDisclosure {
    /// The dispatch provider must enforce this exclusive deadline at I/O time.
    pub fn valid_until(&self) -> UnixTimestamp {
        *self.valid_until
    }

    /// Durable evidence for history correlation.
    pub const fn receipt(&self) -> &ConsentReceipt {
        &self.receipt
    }
    /// Exact final attributes authorized for transmission.
    pub const fn disclosed_scope(&self) -> &ConsentScope {
        self.authorization.disclosed_scope()
    }
}
impl CapturedReceiptConsent {
    /// Compare the context in force at response generation and authorize actual scope.
    pub fn authorize_final_disclosure(
        self,
        live_request: Option<&VerifiedWalletRequest>,
        scope: ConsentScope,
        context_digest: [u8; 32],
        clock: &dyn TrustedConsentClock,
    ) -> ConsentResult<AuthorizedReceiptDisclosure> {
        match (self.receipt.reader.as_ref(), live_request) {
            (None, Some(request)) => self.consent.validate_live_request(request)?,
            (Some(_), None) => {}
            _ => {
                return Err(ConsentError::new(
                    ConsentErrorReason::RequestBindingMismatch,
                ))
            }
        }
        let now = clock.now();
        if now < self.receipt.capture.captured_at || now >= *self.valid_until {
            return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
        }
        if *self.context_digest != context_digest {
            return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
        }
        Ok(AuthorizedReceiptDisclosure {
            valid_until: self.valid_until,
            authorization: self.consent.authorize_scope(scope)?,
            receipt: self.receipt,
        })
    }
    /// Borrow evidence; it cannot be turned back into a single-use authorization.
    pub const fn receipt(&self) -> &ConsentReceipt {
        &self.receipt
    }
}
fn append(bytes: &mut Vec<u8>, value: &[u8]) -> ConsentResult<()> {
    let len = u32::try_from(value.len())
        .map_err(|_| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
    let size = bytes
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(value.len()))
        .ok_or_else(|| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
    if size > MAX_POLICY_TRANSCRIPT_BYTES {
        return Err(ConsentError::new(ConsentErrorReason::ScopeTooLarge));
    }
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}
/// Deterministic context digest. Text parsing and policy semantics remain with SSI.
pub fn consent_policy_digest(context: &ConsentPolicyContext) -> ConsentResult<[u8; 32]> {
    if context.purpose.as_str().is_empty()
        || context.policies.len() > MAX_CONSENT_POLICIES
        || context.transaction_digest == [0; 32]
    {
        return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(MAX_POLICY_TRANSCRIPT_BYTES)
        .map_err(|_| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
    append(&mut bytes, CONTEXT_DOMAIN)?;
    append(&mut bytes, context.purpose.as_str().as_bytes())?;
    match context.retention {
        ConsentRetention::NoRetention => append(&mut bytes, &[1])?,
        ConsentRetention::Until(time) => {
            append(&mut bytes, &[2])?;
            append(&mut bytes, &time.as_seconds().to_be_bytes())?;
        }
    }
    let count = u32::try_from(context.policies.len())
        .map_err(|_| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
    append(&mut bytes, &count.to_be_bytes())?;
    let mut prior = None;
    for choice in &context.policies {
        if choice.id.as_str().is_empty()
            || choice.version.as_str().is_empty()
            || choice.document_digest == [0; 32]
            || (choice.mandatory && !choice.accepted)
            || prior.is_some_and(|id: &NonEmptyIdentifier| id >= &choice.id)
        {
            return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
        }
        prior = Some(&choice.id);
        append(&mut bytes, choice.id.as_str().as_bytes())?;
        append(&mut bytes, choice.version.as_str().as_bytes())?;
        append(&mut bytes, &choice.document_digest)?;
        append(
            &mut bytes,
            &[u8::from(choice.mandatory), u8::from(choice.accepted)],
        )?;
    }
    append(&mut bytes, &context.transaction_digest)?;
    Ok(crypto_sha2_256::digest(&bytes).into_bytes())
}
/// Add durable receipt capture to an already verified OpenID4VP consent request.
pub fn prepare_online_receipt_consent(prepared: PreparedConsentRequest) -> PreparedReceiptConsent {
    let context_digest = prepared.request().request_digest;
    PreparedReceiptConsent {
        prepared,
        policy: None,
        policy_authorization: None,
        reader: None,
        context_digest: Zeroizing::new(context_digest),
    }
}
/// Prepare proximity consent only from authenticated, fresh reader facts. The
/// digest binds reader identity, certificate, request and SessionTranscript.
pub fn prepare_reader_receipt_consent<V: ReaderAuthorizationVerifier>(
    verifier: &V,
    evidence: &V::Evidence,
    actions: Vec<ConsentAction>,
    unregistered_policy: UnregisteredAttributePolicy,
    now: UnixTimestamp,
) -> ConsentResult<PreparedReceiptConsent> {
    let facts = verifier.verify_reader(evidence, now)?;
    let binding = &facts.binding;
    if binding.reader_id != facts.entitlement.relying_party_id
        || binding.authenticated_at > now
        || now >= binding.valid_until
        || binding.valid_until > facts.entitlement.valid_until
        || binding.certificate_digest == [0; 32]
        || binding.session_digest == [0; 32]
        || binding.request_digest == [0; 32]
    {
        return Err(ConsentError::new(
            ConsentErrorReason::ReaderAuthenticationRejected,
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(MAX_POLICY_TRANSCRIPT_BYTES)
        .map_err(|_| ConsentError::new(ConsentErrorReason::ScopeTooLarge))?;
    for value in [
        READER_DOMAIN,
        binding.reader_id.as_str().as_bytes(),
        &binding.certificate_digest,
        &binding.session_digest,
        &binding.request_digest,
    ] {
        append(&mut bytes, value)?;
    }
    append(
        &mut bytes,
        &binding.authenticated_at.as_seconds().to_be_bytes(),
    )?;
    append(&mut bytes, &binding.valid_until.as_seconds().to_be_bytes())?;
    let digest = crypto_sha2_256::digest(&bytes).into_bytes();
    let prepared = prepare_consent_request_from_entitlement(
        &facts.entitlement,
        facts.requested_scope.clone(),
        actions,
        facts.request_nonce.clone(),
        digest,
        unregistered_policy,
        now,
    )?;
    Ok(PreparedReceiptConsent {
        prepared,
        policy: None,
        policy_authorization: None,
        reader: Some(facts.binding.clone()),
        context_digest: Zeroizing::new(digest),
    })
}
/// Bind provider-authenticated terms before holder interaction. Altering any
/// purpose, retention, version, choice or transaction assignment changes approval.
pub fn bind_receipt_policy(
    mut prepared: PreparedReceiptConsent,
    context: ConsentPolicyContext,
    verifier: &dyn ConsentPolicyVerifier,
    now: UnixTimestamp,
) -> ConsentResult<PreparedReceiptConsent> {
    if prepared.policy.is_some() {
        return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
    }
    let digest = consent_policy_digest(&context)?;
    let authorization = verifier.verify_policy_context(prepared.request(), &context, now)?;
    if authorization.relying_party_id != prepared.request().relying_party_id
        || authorization.request_digest != prepared.request().request_digest
        || authorization.policy_digest != digest
        || authorization.verified_at > now
        || now >= authorization.valid_until
        || matches!(context.retention, ConsentRetention::Until(until) if until <= now)
    {
        return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
    }
    let mut transcript = Zeroizing::new(Vec::with_capacity(64));
    transcript.extend_from_slice(&*prepared.context_digest);
    transcript.extend_from_slice(&digest);
    prepared.context_digest = Zeroizing::new(crypto_sha2_256::digest(&transcript).into_bytes());
    prepared.policy = Some(context);
    prepared.policy_authorization = Some(authorization);
    Ok(prepared)
}
/// Claim the nonce and append its complete receipt before returning authorization.
/// Capture must echo the prepared reader/session and context, not new caller facts.
pub fn capture_receipt_consent(
    prepared: PreparedReceiptConsent,
    capture: ConsentCapture,
    approved_context_digest: [u8; 32],
    reader: Option<&ReaderSessionBinding>,
    clock: &dyn TrustedConsentClock,
    store: &mut dyn ConsentCaptureStore,
) -> ConsentResult<CapturedReceiptConsent> {
    let now = clock.now();
    if approved_context_digest != *prepared.context_digest
        || reader != prepared.reader.as_ref()
        || prepared
            .reader
            .as_ref()
            .is_some_and(|binding| now < binding.authenticated_at || now >= binding.valid_until)
        || prepared
            .policy_authorization
            .as_ref()
            .is_some_and(|auth| now < auth.verified_at || now >= auth.valid_until)
        || prepared.policy.as_ref().is_some_and(
            |ctx| matches!(ctx.retention, ConsentRetention::Until(until) if until <= now),
        )
    {
        return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
    }
    // Freeze one trusted observation: a second clock read must not authorize an
    // expired policy after the first read passed its freshness check.
    struct ObservedClock(UnixTimestamp);
    impl TrustedConsentClock for ObservedClock {
        fn now(&self) -> UnixTimestamp {
            self.0
        }
    }
    let capture = validate_prepared_capture(&prepared.prepared, capture, &ObservedClock(now))?;
    let mut valid_until = prepared.prepared.authorization_valid_until();
    if let Some(reader) = &prepared.reader {
        valid_until = core::cmp::min(valid_until, reader.valid_until);
    }
    if let Some(policy) = &prepared.policy_authorization {
        valid_until = core::cmp::min(valid_until, policy.valid_until);
    }
    if let Some(context) = &prepared.policy {
        if let ConsentRetention::Until(until) = context.retention {
            valid_until = core::cmp::min(valid_until, until);
        }
    }
    if now >= valid_until {
        return Err(ConsentError::new(ConsentErrorReason::PolicyContextMismatch));
    }
    let receipt = ConsentReceipt {
        capture,
        policy: prepared.policy,
        reader: prepared.reader,
    };
    // Same namespace and deadline as a plain capture of this request, so the
    // two forms cannot each claim it once.
    store
        .claim_capture(&prepared.prepared.consent_claim(), Some(&receipt))
        .map_err(|error| {
            ConsentError::new(match error.reason {
                ConsentCaptureStoreErrorReason::AlreadyClaimed => {
                    ConsentErrorReason::CaptureAlreadyUsed
                }
                ConsentCaptureStoreErrorReason::Unavailable
                | ConsentCaptureStoreErrorReason::ReceiptUnsupported => {
                    ConsentErrorReason::ReceiptStoreUnavailable
                }
            })
        })?;
    Ok(CapturedReceiptConsent {
        valid_until: Zeroizing::new(valid_until),
        consent: prepared.prepared.captured(receipt.capture.clone()),
        receipt,
        context_digest: Zeroizing::new(approved_context_digest),
    })
}
#[cfg(test)]
#[path = "receipt_tests.rs"]
mod tests;

// Every sensitive field has its own drop-time owner. The marker preserves
// consuming transitions without adding an outer Drop implementation.
impl ZeroizeOnDrop for PreparedReceiptConsent {}
impl ZeroizeOnDrop for CapturedReceiptConsent {}
impl ZeroizeOnDrop for AuthorizedReceiptDisclosure {}
