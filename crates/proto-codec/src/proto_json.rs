// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated ProtoJSON boundary for canonical Wallet operation messages.

use core::cell::Cell;
use core::fmt;
use std::io::{self, Write};

use buffa::Message;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ProtoError, ProtoErrorReason, ProtoResult, MAX_WALLET_PROTO_JSON_BYTES,
    MAX_WALLET_PROTO_JSON_NESTING_DEPTH, MAX_WALLET_PROTO_MESSAGE_BYTES,
};

mod private {
    pub trait Sealed {}
}

const MAX_WALLET_PROTO_JSON_ELEMENTS: usize = 65_536;

struct BoundedJsonWriter {
    bytes: Zeroizing<Vec<u8>>,
    exceeded_limit: bool,
}

impl BoundedJsonWriter {
    fn new() -> ProtoResult<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        // Reserve the full policy bound before writing sensitive JSON so
        // growth cannot leave earlier plaintext copies in freed allocations.
        bytes
            .try_reserve_exact(MAX_WALLET_PROTO_JSON_BYTES)
            .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
        Ok(Self {
            bytes,
            exceeded_limit: false,
        })
    }

    fn into_string(mut self) -> ProtoResult<Zeroizing<String>> {
        let bytes = core::mem::take(&mut *self.bytes);
        match String::from_utf8(bytes) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                Err(ProtoError::new(ProtoErrorReason::JsonSerialize))
            }
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next_length) = self.bytes.len().checked_add(buffer.len()) else {
            self.exceeded_limit = true;
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        };
        if next_length > MAX_WALLET_PROTO_JSON_BYTES {
            self.exceeded_limit = true;
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct SensitiveJsonValue(JsonValue);

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::String(value) => value.zeroize(),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(values) => {
            let owned = core::mem::take(values);
            for (mut key, mut value) in owned {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

/// Generated Wallet messages approved as top-level public ProtoJSON values.
///
/// The trait is sealed so callers cannot route arbitrary Serde models through
/// this codec and accidentally create a second Wallet JSON contract.
pub trait WalletProtoJson: Message + Serialize + DeserializeOwned + private::Sealed {}

macro_rules! impl_wallet_proto_json {
    ($($message:path),+ $(,)?) => {
        $(
            impl private::Sealed for $message {}
            impl WalletProtoJson for $message {}
        )+
    };
}

impl_wallet_proto_json!(
    pb::WalletOperationRequest,
    pb::WalletOperationResult,
    pb::WalletOperationResponse,
);

fn ensure_message_size<M: Message>(message: &M) -> ProtoResult<()> {
    let max_bytes = u32::try_from(MAX_WALLET_PROTO_MESSAGE_BYTES)
        .map_err(|_| ProtoError::new(ProtoErrorReason::MessageTooLarge))?;
    match message.try_encoded_len() {
        Ok(encoded_len) if encoded_len <= max_bytes => Ok(()),
        Ok(_) | Err(_) => Err(ProtoError::new(ProtoErrorReason::MessageTooLarge)),
    }
}

#[derive(Clone, Copy)]
enum JsonBoundaryFailure {
    DuplicateKey,
    ElementLimitExceeded,
    NestingTooDeep,
}

#[derive(Clone, Copy)]
struct StrictJsonSeed<'a> {
    depth: usize,
    element_count: &'a Cell<usize>,
    failure: &'a Cell<Option<JsonBoundaryFailure>>,
}

impl StrictJsonSeed<'_> {
    fn child<E: serde::de::Error>(self) -> Result<Self, E> {
        let depth = self.depth.checked_add(1).ok_or_else(|| {
            self.failure.set(Some(JsonBoundaryFailure::NestingTooDeep));
            E::custom("Wallet ProtoJSON nesting exceeds policy")
        })?;
        Ok(Self {
            depth,
            element_count: self.element_count,
            failure: self.failure,
        })
    }
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let element_count = self.element_count.get().checked_add(1).ok_or_else(|| {
            self.failure
                .set(Some(JsonBoundaryFailure::ElementLimitExceeded));
            D::Error::custom("Wallet ProtoJSON element count exceeds policy")
        })?;
        if element_count > MAX_WALLET_PROTO_JSON_ELEMENTS {
            self.failure
                .set(Some(JsonBoundaryFailure::ElementLimitExceeded));
            return Err(D::Error::custom(
                "Wallet ProtoJSON element count exceeds policy",
            ));
        }
        self.element_count.set(element_count);
        if self.depth > MAX_WALLET_PROTO_JSON_NESTING_DEPTH {
            self.failure.set(Some(JsonBoundaryFailure::NestingTooDeep));
            return Err(D::Error::custom("Wallet ProtoJSON nesting exceeds policy"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { seed: self })
    }
}

struct StrictJsonVisitor<'a> {
    seed: StrictJsonSeed<'a>,
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value within Wallet boundary policy")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(JsonNumber::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(JsonNumber::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        JsonNumber::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite Wallet ProtoJSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.seed.child()?.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // Keep the partial tree under a wiping owner while serde can still
        // fail on a later element.
        let mut values = SensitiveJsonValue(JsonValue::Array(Vec::new()));
        let child = self.seed.child()?;
        while let Some(value) = sequence.next_element_seed(child)? {
            let JsonValue::Array(items) = &mut values.0 else {
                return Err(A::Error::custom("invalid Wallet ProtoJSON array state"));
            };
            items.push(value);
        }
        Ok(core::mem::replace(&mut values.0, JsonValue::Null))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = SensitiveJsonValue(JsonValue::Object(JsonMap::new()));
        let child = self.seed.child()?;
        while let Some(mut key) = object.next_key::<String>()? {
            let JsonValue::Object(entries) = &mut values.0 else {
                return Err(A::Error::custom("invalid Wallet ProtoJSON object state"));
            };
            if entries.contains_key(&key) {
                self.seed
                    .failure
                    .set(Some(JsonBoundaryFailure::DuplicateKey));
                key.zeroize();
                return Err(A::Error::custom("duplicate Wallet ProtoJSON object key"));
            }
            let value = match object.next_value_seed(child) {
                Ok(value) => value,
                Err(error) => {
                    key.zeroize();
                    return Err(error);
                }
            };
            entries.insert(key, value);
        }
        Ok(core::mem::replace(&mut values.0, JsonValue::Null))
    }
}

fn parse_strict_json(json: &str) -> ProtoResult<SensitiveJsonValue> {
    if json.len() > MAX_WALLET_PROTO_JSON_BYTES {
        return Err(ProtoError::new(ProtoErrorReason::MessageTooLarge));
    }

    let failure = Cell::new(None);
    let element_count = Cell::new(0);
    let seed = StrictJsonSeed {
        depth: 0,
        element_count: &element_count,
        failure: &failure,
    };
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let value = seed
        .deserialize(&mut deserializer)
        .map_err(|_| match failure.get() {
            Some(JsonBoundaryFailure::DuplicateKey) => {
                ProtoError::new(ProtoErrorReason::JsonDuplicateKey)
            }
            Some(JsonBoundaryFailure::ElementLimitExceeded) => {
                ProtoError::new(ProtoErrorReason::MessageTooLarge)
            }
            Some(JsonBoundaryFailure::NestingTooDeep) => {
                ProtoError::new(ProtoErrorReason::JsonNestingTooDeep)
            }
            None => ProtoError::new(ProtoErrorReason::JsonDeserialize),
        })?;
    let value = SensitiveJsonValue(value);
    deserializer
        .end()
        .map_err(|_| ProtoError::new(ProtoErrorReason::JsonDeserialize))?;
    Ok(value)
}

/// Serialize an approved generated Wallet message using generated ProtoJSON.
pub fn wallet_proto_to_json<M: WalletProtoJson>(message: &M) -> ProtoResult<Zeroizing<String>> {
    ensure_message_size(message)?;
    let mut writer = BoundedJsonWriter::new()?;
    if serde_json::to_writer(&mut writer, message).is_err() {
        return Err(ProtoError::new(if writer.exceeded_limit {
            ProtoErrorReason::MessageTooLarge
        } else {
            ProtoErrorReason::JsonSerialize
        }));
    }
    let json = writer.into_string()?;
    parse_strict_json(&json).map_err(|error| match error.reason {
        ProtoErrorReason::JsonNestingTooDeep => error,
        _ => ProtoError::new(ProtoErrorReason::JsonSerialize),
    })?;
    Ok(json)
}

/// Deserialize generated Wallet ProtoJSON under strict boundary policy.
pub fn wallet_proto_from_json<M: WalletProtoJson>(json: &str) -> ProtoResult<M> {
    let input_value = parse_strict_json(json)?;
    let message: M = M::deserialize(&input_value.0)
        .map_err(|_| ProtoError::new(ProtoErrorReason::JsonDeserialize))?;
    ensure_message_size(&message)?;
    let canonical_value = SensitiveJsonValue(
        serde_json::to_value(&message)
            .map_err(|_| ProtoError::new(ProtoErrorReason::JsonDeserialize))?,
    );
    if canonical_value.0 != input_value.0 {
        return Err(ProtoError::new(ProtoErrorReason::JsonDeserialize));
    }
    Ok(message)
}
