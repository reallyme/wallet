// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical public-key comparison for installation-bound hardware records.

use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::did::v1 as did_pb;

fn subject_public_key_bytes(subject_key: &credential_pb::PublicKeyRef) -> Option<&[u8]> {
    use credential_pb::__buffa::oneof::public_key_material::Representation;

    match subject_key
        .public_key
        .as_option()?
        .representation
        .as_ref()?
    {
        Representation::Raw(value) => Some(value.bytes.as_slice()),
        Representation::SubjectPublicKeyInfoDer(value)
        | Representation::JwkJson(value)
        | Representation::CoseKey(value) => Some(value.as_slice()),
        Representation::Multikey(_) => None,
    }
}

pub(super) fn hardware_key_material_matches(
    subject_key: &credential_pb::PublicKeyRef,
    method: Option<&did_pb::VerificationMethod>,
    platform_key: &[u8],
) -> bool {
    let Some(subject_material) = subject_key.public_key.as_option() else {
        return false;
    };
    let Some(algorithm) = subject_material.alg.as_known() else {
        return false;
    };
    let Some(subject_bytes) = subject_public_key_bytes(subject_key) else {
        return false;
    };
    public_keys_equal(algorithm, subject_bytes, platform_key)
        && subject_key_matches_method_material(subject_key, method)
}

pub(super) fn subject_key_matches_method_material(
    subject_key: &credential_pb::PublicKeyRef,
    method: Option<&did_pb::VerificationMethod>,
) -> bool {
    let Some(subject_material) = subject_key.public_key.as_option() else {
        return false;
    };
    let Some(algorithm) = subject_material.alg.as_known() else {
        return false;
    };
    let Some(subject_bytes) = subject_public_key_bytes(subject_key) else {
        return false;
    };
    let Some(did_pb::verification_method::PublicKey::PublicKeyJwk(method_jwk)) =
        method.and_then(|value| value.public_key.as_ref())
    else {
        // Opaque multibase values cannot be safely compared without a
        // multicodec decoder, so this boundary fails closed.
        return false;
    };
    public_keys_equal(algorithm, subject_bytes, method_jwk.public_key.as_slice())
}

fn public_keys_equal(algorithm: credential_pb::Algorithm, left: &[u8], right: &[u8]) -> bool {
    if algorithm != credential_pb::Algorithm::ALGORITHM_P_256 {
        return left == right;
    }
    let Some(left) = canonical_p256_public_key(left) else {
        return false;
    };
    let Some(right) = canonical_p256_public_key(right) else {
        return false;
    };
    left == right
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn canonical_p256_public_key(value: &[u8]) -> Option<Vec<u8>> {
    match value.len() {
        33 => crypto_p256::decompress_public_key(value)
            .ok()
            .and_then(|uncompressed| crypto_p256::compress_public_key(&uncompressed).ok()),
        65 => crypto_p256::compress_public_key(value).ok(),
        _ => None,
    }
}

#[cfg(not(any(feature = "native", feature = "wasm")))]
fn canonical_p256_public_key(_value: &[u8]) -> Option<Vec<u8>> {
    None
}
