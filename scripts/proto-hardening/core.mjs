// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";

/**
 * Apply deterministic security transformations to fresh Buffa message output.
 *
 * Repository wrappers own schema paths and CLI policy. This core owns only the
 * reusable transformation mechanics so sibling proto-first repositories can
 * review and pin one narrowly scoped implementation.
 */
export function hardenGeneratedProto({
  additionalOwnedPaths = [],
  checkIdempotent = false,
  contracts,
  failurePrefix,
  sensitiveOneofs = [],
}) {
  const safeFailurePrefix = typeof failurePrefix === "string" && failurePrefix.length > 0
    ? failurePrefix
    : "generated protobuf hardening failed";

  function fail(message) {
    console.error(`${safeFailurePrefix}: ${message}`);
    process.exit(1);
  }

  function writeGeneratedFile(path, contents) {
    // Generate beside the destination and rename only after the complete file
    // is durable in userspace. This prevents concurrent policy/readiness jobs
    // from observing a truncated generated source during writeFileSync.
    const temporaryPath = `${path}.reallyme-hardening-${process.pid}`;
    try {
      writeFileSync(temporaryPath, contents, { flag: "wx", mode: 0o644 });
      renameSync(temporaryPath, path);
    } catch {
      rmSync(temporaryPath, { force: true });
      fail("could not atomically replace generated source");
    }
  }

  if (!Array.isArray(contracts) || contracts.length === 0) {
    fail("at least one generated contract is required");
  }
  if (!Array.isArray(additionalOwnedPaths)) {
    fail("additional generated paths must be an array");
  }
  if (!Array.isArray(sensitiveOneofs)) {
    fail("sensitive oneof configuration must be an array");
  }
  for (const contract of contracts) {
    if (
      contract === null
      || typeof contract !== "object"
      || Array.isArray(contract)
      || typeof contract.proto !== "string"
      || contract.proto.length === 0
      || typeof contract.owned !== "string"
      || contract.owned.length === 0
    ) {
      fail("generated contract configuration is invalid");
    }
  }
  if (
    additionalOwnedPaths.some(
      (path) => typeof path !== "string" || path.length === 0,
    )
  ) {
    fail("additional generated path configuration is invalid");
  }
  for (const oneof of sensitiveOneofs) {
    if (
      oneof === null || typeof oneof !== "object" || Array.isArray(oneof) ||
      typeof oneof.path !== "string" || oneof.path.length === 0 ||
      typeof oneof.enumName !== "string" || !/^\w+$/u.test(oneof.enumName) ||
      !Array.isArray(oneof.byteVariants) || oneof.byteVariants.length === 0 ||
      oneof.byteVariants.some((variant) => typeof variant !== "string" || !/^\w+$/u.test(variant))
    ) {
      fail("sensitive oneof configuration is invalid");
    }
  }

function findMatchingBrace(source, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  fail(`missing matching brace after byte offset ${openIndex}`);
}

function braceDepthBefore(source, endIndex) {
  let depth = 0;
  for (let index = 0; index < endIndex; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
    }
  }
  return depth;
}

function parseMessages(path) {
  const source = readFileSync(path, "utf8");
  if (/^[ \t]+message\s+\w+\s*\{/mu.test(source)) {
    fail(`${path} contains a nested message that the hardening pass cannot map safely`);
  }
  if (/^[ \t]*(?:optional|required|repeated\s+)?map\s*</mu.test(source)) {
    fail(`${path} contains a map field that the hardening pass cannot zeroize safely`);
  }
  const messages = new Map();
  const pattern = /^message\s+(\w+)\s*\{/gmu;
  for (const match of source.matchAll(pattern)) {
    const openIndex = source.indexOf("{", match.index);
    const closeIndex = findMatchingBrace(source, openIndex);
    const body = source.slice(openIndex + 1, closeIndex);
    const prefix = source.slice(Math.max(0, match.index - 320), match.index);
    const fields = [...body.matchAll(
      /^\s*(?:(optional|required|repeated)\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/gmu,
    )].map((field) => ({
      repeated: field[1] === "repeated",
      type: field[2],
      name: field[3],
      direct: braceDepthBefore(body, field.index) === 0,
    }));
    messages.set(match[1], {
      fields,
      explicitSensitive: /reallyme\.security:\s*sensitive-owner\s*$/mu.test(prefix),
    });
  }
  return messages;
}

const messagesByContract = new Map();
const allMessages = new Map();
for (const contract of contracts) {
  const messages = parseMessages(contract.proto);
  messagesByContract.set(contract.proto, messages);
  for (const [name, definition] of messages) {
    if (allMessages.has(name)) {
      fail(`duplicate Wallet message name ${name}`);
    }
    allMessages.set(name, definition);
  }
}

const sensitiveMessages = new Set();
for (const [name, definition] of allMessages) {
  if (
    definition.explicitSensitive ||
    definition.fields.some((field) => field.type === "bytes" || field.type === "string")
  ) {
    sensitiveMessages.add(name);
  }
}

// A wrapper is just as sensitive as the local message it owns. This closure
// covers request/result/response envelopes and keeps new wrapper messages from
// silently regaining generated Debug output when the schema grows.
let changed = true;
while (changed) {
  changed = false;
  for (const [name, definition] of allMessages) {
    if (
      !sensitiveMessages.has(name) &&
      definition.fields.some((field) =>
        sensitiveMessages.has(field.type.split(".").at(-1)),
      )
    ) {
      sensitiveMessages.add(name);
      changed = true;
    }
  }
}

const zeroizeUnknownFields = `
fn __reallyme_zeroize_unknown_fields(fields: &mut ::buffa::UnknownFields) {
    for mut field in ::core::mem::take(fields) {
        __reallyme_zeroize_unknown_field_data(&mut field.data);
    }
}

fn __reallyme_zeroize_unknown_field_data(data: &mut ::buffa::UnknownFieldData) {
    match data {
        ::buffa::UnknownFieldData::LengthDelimited(bytes) => {
            ::zeroize::Zeroize::zeroize(bytes);
        }
        ::buffa::UnknownFieldData::Group(fields) => {
            __reallyme_zeroize_unknown_fields(fields);
        }
        ::buffa::UnknownFieldData::Varint(_)
        | ::buffa::UnknownFieldData::Fixed64(_)
        | ::buffa::UnknownFieldData::Fixed32(_) => {}
    }
}

#[doc(hidden)]
#[derive(Clone, Default, PartialEq)]
pub struct __ReallyMeZeroizingUnknownFields(::buffa::UnknownFields);

impl ::core::fmt::Debug for __ReallyMeZeroizingUnknownFields {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("__ReallyMeZeroizingUnknownFields(<redacted>)")
    }
}

impl ::core::convert::From<::buffa::UnknownFields> for __ReallyMeZeroizingUnknownFields {
    fn from(fields: ::buffa::UnknownFields) -> Self {
        Self(fields)
    }
}

impl ::core::ops::Deref for __ReallyMeZeroizingUnknownFields {
    type Target = ::buffa::UnknownFields;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ::core::ops::DerefMut for __ReallyMeZeroizingUnknownFields {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ::core::ops::Drop for __ReallyMeZeroizingUnknownFields {
    fn drop(&mut self) {
        __reallyme_zeroize_unknown_fields(&mut self.0);
    }
}
`;

function hardenDebug(source, messageName, path) {
  const marker = `impl ::core::fmt::Debug for ${messageName} {`;
  const start = source.indexOf(marker);
  if (start < 0) {
    fail(`${path} is missing Debug for ${messageName}`);
  }
  const openIndex = source.indexOf("{", start);
  const closeIndex = findMatchingBrace(source, openIndex);
  const replacement = `impl ::core::fmt::Debug for ${messageName} {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${messageName}(<redacted>)")
    }
}`;
  return `${source.slice(0, start)}${replacement}${source.slice(closeIndex + 1)}`;
}

function rustFieldName(name) {
  const keywords = new Set([
    "as", "break", "const", "continue", "crate", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match",
    "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static",
    "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn",
  ]);
  return keywords.has(name) ? `r#${name}` : name;
}

function parseStructFields(body) {
  const fields = [];
  const lines = body.split("\n");
  let serdeLines = [];
  let collectingSerde = false;
  let pending = null;
  let angleDepth = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#[serde(")) {
      collectingSerde = true;
      serdeLines = [trimmed];
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
      }
      continue;
    }
    if (collectingSerde) {
      serdeLines.push(trimmed);
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
      }
      continue;
    }
    if (pending !== null) {
      pending.parts.push(trimmed);
      for (const character of trimmed) {
        angleDepth += character === "<" ? 1 : character === ">" ? -1 : 0;
      }
      if (trimmed.endsWith(",") && angleDepth === 0) {
        fields.push({
          name: pending.name,
          type: pending.parts.join(" ").replace(/,$/u, "").replace(/\s+/gu, " "),
          serdeAttr: serdeLines.join("\n"),
        });
        pending = null;
        serdeLines = [];
      }
      continue;
    }
    const field = line.match(/^\s+pub\s+((?:r#)?\w+):\s+(.+)$/u);
    if (field === null || field[1] === "__buffa_unknown_fields") {
      continue;
    }
    angleDepth = 0;
    for (const character of field[2]) {
      angleDepth += character === "<" ? 1 : character === ">" ? -1 : 0;
    }
    pending = { name: field[1], parts: [field[2].trim()] };
    if (field[2].trim().endsWith(",") && angleDepth === 0) {
      fields.push({
        name: pending.name,
        type: pending.parts[0].replace(/,$/u, ""),
        serdeAttr: serdeLines.join("\n"),
      });
      pending = null;
      serdeLines = [];
    }
  }
  return fields;
}

function sensitiveFieldKind(type) {
  // Rust formatters may wrap a long generated field type across lines. Type
  // classification is structural, so insignificant whitespace must not turn a
  // supported sensitive container into an unrecognized one.
  const compactType = type.replace(/\s+/gu, "").replace(/,>/gu, ">");
  if (compactType === "::buffa::alloc::string::String") {
    return "string";
  }
  if (compactType === "::buffa::alloc::vec::Vec<u8>") {
    return "bytes";
  }
  if (compactType === "::buffa::alloc::vec::Vec<::buffa::alloc::string::String>") {
    return "strings";
  }
  if (compactType === "::buffa::alloc::vec::Vec<::buffa::alloc::vec::Vec<u8>>") {
    return "bytes_list";
  }
  return null;
}

function wireSerdeAttr(field, sensitive) {
  if (!sensitive) {
    return field.serdeAttr;
  }
  const kind = sensitiveFieldKind(field.type);
  if (kind === null) {
    fail(`unsupported sensitive generated field type ${field.type}`);
  }
  let attr = field.serdeAttr
    .replace(/,?\s*deserialize_with\s*=\s*"[^"]+"/gu, "")
    .replace(/,?\s*\bwith\s*=\s*"[^"]+"/gu, "")
    .replace(/\(\s*,/u, "(");
  const insertion = `deserialize_with = "deserialize_zeroizing_${kind}"`;
  if (attr.includes("#[serde(")) {
    attr = attr.replace(/\)\]$/u, `, ${insertion})]`).replace(/,\s*,/gu, ",");
  } else {
    attr = `#[serde(${insertion})]`;
  }
  return attr;
}

function deserializeHelper(kind) {
  const definitions = {
    string: `        fn deserialize_zeroizing_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::string::String>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::proto_string::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }`,
    bytes: `        fn deserialize_zeroizing_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }`,
    strings: `        fn deserialize_zeroizing_strings<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<::buffa::alloc::string::String>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::null_as_default(deserializer)
                .map(::zeroize::Zeroizing::new)
        }`,
    bytes_list: `        fn deserialize_zeroizing_bytes_list<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<::buffa::alloc::vec::Vec<u8>>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::proto_seq::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }`,
  };
  return definitions[kind];
}

function hardenDeserialize(source, messageName, directFields, path) {
  const customMarker = `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`;
  if (source.includes(customMarker) || source.includes(`impl<'de> serde::Deserialize<'de> for ${messageName} {`)) {
    return source;
  }
  const structMarker = `pub struct ${messageName} {`;
  const structIndex = source.indexOf(structMarker);
  if (structIndex < 0) {
    fail(`${path} is missing struct ${messageName}`);
  }
  const structOpen = source.indexOf("{", structIndex);
  const structClose = findMatchingBrace(source, structOpen);
  const fields = parseStructFields(source.slice(structOpen + 1, structClose));
  const directNames = new Set(directFields.map((field) => rustFieldName(field.name)));
  const sensitiveGeneratedFields = fields.filter((field) => directNames.has(field.name));
  if (sensitiveGeneratedFields.length !== directFields.length) {
    fail(`${path} could not map every sensitive field for ${messageName}`);
  }

  const headerStart = Math.max(0, structIndex - 512);
  const header = source.slice(headerStart, structIndex);
  const rawDerive = "#[derive(::serde::Serialize, ::serde::Deserialize)]";
  const deriveIndex = header.lastIndexOf(rawDerive);
  if (deriveIndex < 0) {
    fail(`${path} is missing generated Deserialize derive for ${messageName}`);
  }
  const absoluteDeriveIndex = headerStart + deriveIndex;
  source = `${source.slice(0, absoluteDeriveIndex)}#[derive(::serde::Serialize)]${source.slice(absoluteDeriveIndex + rawDerive.length)}`;

  const kinds = [...new Set(sensitiveGeneratedFields.map((field) => sensitiveFieldKind(field.type)))];
  const helpers = kinds.map(deserializeHelper).join("\n\n");
  const wireFields = fields.map((field) => {
    const sensitive = directNames.has(field.name);
    const type = sensitive ? `::zeroize::Zeroizing<${field.type}>` : field.type;
    return `${wireSerdeAttr(field, sensitive)}
            ${field.name}: ${type},`;
  }).join("\n");
  const assignments = fields.map((field) => {
    const value = directNames.has(field.name)
      ? `::core::mem::take(&mut *wire.${field.name})`
      : `wire.${field.name}`;
    return `            ${field.name}: ${value},`;
  }).join("\n");
  const wireBinding = directFields.length === 0 ? "wire" : "mut wire";
  const deserialize = `impl<'de> ::serde::Deserialize<'de> for ${messageName} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
${helpers}

        #[derive(Default, ::serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
${wireFields}
        }

        let ${wireBinding} = Wire::deserialize(deserializer)?;
        ::core::result::Result::Ok(Self {
${assignments}
            __buffa_unknown_fields: ::core::default::Default::default(),
        })
    }
}
`;
  const inherentIndex = source.indexOf(`impl ${messageName} {`, structClose);
  if (inherentIndex < 0) {
    fail(`${path} is missing inherent impl for ${messageName}`);
  }
  return `${source.slice(0, inherentIndex)}${deserialize}${source.slice(inherentIndex)}`;
}

function hardenDrop(source, messageName, directFields, path) {
  const marker = `impl ::core::ops::Drop for ${messageName} {`;
  const zeroizeMarker = `impl ::zeroize::ZeroizeOnDrop for ${messageName} {}`;
  if (source.includes(marker)) {
    if (source.includes(zeroizeMarker)) {
      return source;
    }
    const start = source.indexOf(marker);
    const openIndex = source.indexOf("{", start);
    const closeIndex = findMatchingBrace(source, openIndex);
    return `${source.slice(0, closeIndex + 1)}\n${zeroizeMarker}${source.slice(closeIndex + 1)}`;
  }
  const inherentMarker = `impl ${messageName} {`;
  const inherentIndex = source.indexOf(inherentMarker);
  if (inherentIndex < 0) {
    fail(`${path} is missing inherent impl for ${messageName}`);
  }
  const fieldLines = directFields
    .map((field) => `        ::zeroize::Zeroize::zeroize(&mut self.${rustFieldName(field.name)});`)
    .join("\n");
  const fieldPrefix = fieldLines.length === 0 ? "" : `${fieldLines}\n`;
  const drop = `impl ::core::ops::Drop for ${messageName} {
    fn drop(&mut self) {
${fieldPrefix}        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);
    }
}
${zeroizeMarker}
`;
  return `${source.slice(0, inherentIndex)}${drop}${source.slice(inherentIndex)}`;
}

function hardenZeroizeMarker(source, messageName, path) {
  const marker = `impl ::zeroize::ZeroizeOnDrop for ${messageName} {}`;
  if (source.includes(marker)) {
    return source;
  }
  const inherentIndex = source.indexOf(`impl ${messageName} {`);
  if (inherentIndex < 0) {
    fail(`${path} is missing inherent impl for ${messageName}`);
  }
  return `${source.slice(0, inherentIndex)}${marker}\n${source.slice(inherentIndex)}`;
}

function hardenUnknownFieldStorage(source, messageName, path) {
  const structIndex = source.indexOf(`pub struct ${messageName} {`);
  if (structIndex < 0) {
    fail(`${path} is missing struct ${messageName}`);
  }
  const structOpen = source.indexOf("{", structIndex);
  const structClose = findMatchingBrace(source, structOpen);
  const raw = "pub __buffa_unknown_fields: ::buffa::UnknownFields,";
  const hardened = "pub __buffa_unknown_fields: __ReallyMeZeroizingUnknownFields,";
  const body = source.slice(structOpen + 1, structClose);
  if (body.includes(hardened)) {
    return source;
  }
  if (!body.includes(raw)) {
    fail(`${path} is missing unknown-field storage for ${messageName}`);
  }
  const fieldIndex = source.indexOf(raw, structOpen);
  return `${source.slice(0, fieldIndex)}${hardened}${source.slice(fieldIndex + raw.length)}`;
}

function hardenClear(source, messageName, directFields, path) {
  const structIndex = source.indexOf(`pub struct ${messageName} {`);
  const clearIndex = source.indexOf("fn clear(&mut self) {", structIndex);
  if (structIndex < 0 || clearIndex < 0) {
    fail(`${path} is missing clear for ${messageName}`);
  }
  const openIndex = source.indexOf("{", clearIndex);
  const closeIndex = findMatchingBrace(source, openIndex);
  let body = source.slice(clearIndex, closeIndex + 1);
  for (const field of directFields) {
    body = body.replace(
      `self.${rustFieldName(field.name)}.clear();`,
      `::zeroize::Zeroize::zeroize(&mut self.${rustFieldName(field.name)});`,
    );
  }
  body = body.replace(
    "self.__buffa_unknown_fields.clear();",
    "__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  );
  return `${source.slice(0, clearIndex)}${body}${source.slice(closeIndex + 1)}`;
}

function hardenOwned(contract, insertUnknownFieldHelpers) {
  let source = readFileSync(contract.owned, "utf8");
  if (insertUnknownFieldHelpers && !source.includes("fn __reallyme_zeroize_unknown_fields")) {
    const headerEnd = source.indexOf("\n", source.indexOf("// source:"));
    if (headerEnd < 0) {
      fail(`${contract.owned} is missing its generated header`);
    }
    source = `${source.slice(0, headerEnd + 1)}${zeroizeUnknownFields}${source.slice(headerEnd + 1)}`;
  }
  const messages = messagesByContract.get(contract.proto);
  for (const [messageName, definition] of messages) {
    if (!sensitiveMessages.has(messageName)) {
      continue;
    }
    const directFields = definition.fields.filter(
      (field) => field.direct && (field.type === "bytes" || field.type === "string"),
    );
    source = hardenDebug(source, messageName, contract.owned);
    source = hardenClear(source, messageName, directFields, contract.owned);
    if (directFields.length > 0) {
      source = hardenDeserialize(source, messageName, directFields, contract.owned);
      source = hardenDrop(source, messageName, directFields, contract.owned);
    } else {
      source = hardenUnknownFieldStorage(source, messageName, contract.owned);
      source = hardenZeroizeMarker(source, messageName, contract.owned);
    }
  }
  writeGeneratedFile(contract.owned, hardenJsonErrors(source));
}

function hardenJsonErrors(source) {
  return source
    .replaceAll(
      `::serde::de::Error::custom(
                            ::buffa::alloc::format!("enum value {v} out of i32 range"),
                        )`,
      `::serde::de::Error::custom("enum value out of i32 range")`,
    )
    .replaceAll(
      `::serde::de::Error::custom(
                            ::buffa::alloc::format!("unknown enum value {v32}"),
                        )`,
      `::serde::de::Error::custom("unknown enum value")`,
    )
    .replaceAll("#[serde(default)]", "#[serde(default, deny_unknown_fields)]")
    .replaceAll(
      `                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }`,
      `                        _ => {
                            return Err(serde::de::Error::custom("unknown field"));
                        }`,
    );
}

function hardenSensitiveOneof(source, oneof) {
  const enumMarker = `pub enum ${oneof.enumName} {`;
  const enumIndex = source.indexOf(enumMarker);
  if (enumIndex < 0) {
    fail(`${oneof.path} is missing sensitive oneof ${oneof.enumName}`);
  }
  const enumClose = findMatchingBrace(source, source.indexOf("{", enumIndex));
  const enumBody = source.slice(enumIndex, enumClose);
  for (const variant of oneof.byteVariants) {
    if (!enumBody.includes(`${variant}(::buffa::alloc::vec::Vec<u8>)`)) {
      fail(`${oneof.path} has changed sensitive oneof variant ${variant}`);
    }
  }
  const marker = `impl ::zeroize::ZeroizeOnDrop for ${oneof.enumName} {}`;
  if (source.includes(marker)) {
    return source;
  }
  const wipe = oneof.byteVariants.length === 1
    ? `if let Self::${oneof.byteVariants[0]}(bytes) = self {
                ::zeroize::Zeroize::zeroize(bytes);
            }`
    : `match self {
${oneof.byteVariants.map(
  (variant) => `                Self::${variant}(bytes) => ::zeroize::Zeroize::zeroize(bytes),`,
).join("\n")}
                _ => {}
            }`;
  const drop = `
    impl ::core::ops::Drop for ${oneof.enumName} {
        fn drop(&mut self) {
            ${wipe}
        }
    }
    ${marker}
`;
  return `${source.slice(0, enumClose + 1)}${drop}${source.slice(enumClose + 1)}`;
}

const generatedPaths = [
  ...contracts.map((contract) => contract.owned),
  ...additionalOwnedPaths,
  ...sensitiveOneofs.map((oneof) => oneof.path),
];
const before = checkIdempotent
  ? new Map(generatedPaths.map((path) => [path, readFileSync(path)]))
  : null;

for (const [index, contract] of contracts.entries()) {
  hardenOwned(contract, index === 0);
}
for (const path of additionalOwnedPaths) {
  writeGeneratedFile(path, hardenJsonErrors(readFileSync(path, "utf8")));
}
for (const oneof of sensitiveOneofs) {
  writeGeneratedFile(oneof.path, hardenSensitiveOneof(readFileSync(oneof.path, "utf8"), oneof));
}

if (before !== null) {
  for (const [path, original] of before) {
    if (!original.equals(readFileSync(path))) {
      fail("generated Wallet protobuf hardening is not idempotent");
    }
  }
}
}
