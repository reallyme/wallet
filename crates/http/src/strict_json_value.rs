// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Duplicate-rejecting JSON value for opaque protocol payloads.

use core::fmt;

use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(super) struct StrictJsonValue(JsonValue);

impl StrictJsonValue {
    pub(super) const fn as_value(&self) -> &JsonValue {
        &self.0
    }

    pub(super) fn zeroize(&mut self) {
        zeroize_json_value(&mut self.0);
    }

    fn into_value(mut self) -> JsonValue {
        core::mem::replace(&mut self.0, JsonValue::Null)
    }
}

impl Zeroize for StrictJsonValue {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

impl Drop for StrictJsonValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for StrictJsonValue {}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor).map(Self)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
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
        E: DeError,
    {
        JsonNumber::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_string(value.to_owned())
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
        deserializer.deserialize_any(Self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.into_value());
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = JsonMap::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            let value = object.next_value::<StrictJsonValue>()?;
            values.insert(key, value.into_value());
        }
        Ok(JsonValue::Object(values))
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::String(text) => text.zeroize(),
        JsonValue::Array(values) => values.iter_mut().for_each(zeroize_json_value),
        JsonValue::Object(values) => {
            let old = core::mem::take(values);
            for (mut key, mut nested) in old {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}
