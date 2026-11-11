#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

const read = (path) => readFileSync(resolve(root, path), "utf8");

const requireText = (path, text) => {
  if (!read(path).includes(text)) {
    failures.push(`${path}: missing required boundary marker ${JSON.stringify(text)}`);
  }
};

const rejectText = (path, text) => {
  if (read(path).includes(text)) {
    failures.push(`${path}: contains forbidden boundary text ${JSON.stringify(text)}`);
  }
};

const requireFile = (path) => {
  const absolute = resolve(root, path);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) {
    failures.push(`${path}: required file is missing`);
  }
};

const rejectPath = (path) => {
  if (existsSync(resolve(root, path))) {
    failures.push(`${path}: platform or legacy path must not exist in Wallet`);
  }
};

const rustFiles = (directory) => {
  const files = [];
  for (const entry of readdirSync(resolve(root, directory))) {
    const path = `${directory}/${entry}`;
    const status = statSync(resolve(root, path));
    if (status.isDirectory()) {
      files.push(...rustFiles(path));
    } else if (entry.endsWith(".rs")) {
      files.push(path);
    }
  }
  return files;
};

const productionSource = (path) => {
  const fileName = path.slice(path.lastIndexOf("/") + 1);
  if (
    path.includes("/tests/")
    || fileName === "test.rs"
    || fileName === "tests.rs"
    || fileName.endsWith("_test.rs")
    || fileName.endsWith("_tests.rs")
  ) {
    return "";
  }
  const source = read(path);
  const testModule = source.indexOf("#[cfg(test)]");
  return testModule === -1 ? source : source.slice(0, testModule);
};

const rejectDirectJsonCalls = (directories, allowlist) => {
  const forbidden = ["serde_json::from_", "serde_json::to_", "serde_json::json!"];
  for (const directory of directories) {
    for (const path of rustFiles(directory)) {
      if (allowlist.has(path)) {
        continue;
      }
      const source = productionSource(path);
      for (const text of forbidden) {
        if (source.includes(text)) {
          failures.push(`${path}: direct JSON boundary call ${JSON.stringify(text)}`);
        }
      }
    }
  }
};

const rejectProductionMarkers = (directories, markers) => {
  for (const directory of directories) {
    for (const path of rustFiles(directory)) {
      const source = productionSource(path);
      for (const marker of markers) {
        if (source.includes(marker)) {
          failures.push(`${path}: deprecated compatibility marker ${JSON.stringify(marker)}`);
        }
      }
    }
  }
};

for (const path of [
  "crates/wallet/Cargo.toml",
  "crates/wallet/src/lib.rs",
  "crates/proto/proto/reallyme/wallet/v1/errors.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto",
  "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
  "crates/proto/src/lib.rs",
  "crates/proto-codec/src/lib.rs",
  "crates/proto-codec/src/proto_json.rs",
  "crates/proto/tests/fixtures/wallet-operation-v1-golden.json",
  "crates/proto/tests/fixtures/wallet-provider-v1-golden.txt",
  "crates/proto/tests/fixtures/protojson/get-credential-request.json",
  "crates/proto/tests/fixtures/protojson/delete-credential-success-response.json",
  "crates/proto/tests/fixtures/protojson/malicious-duplicate-operation.json",
  "crates/proto/tests/fixtures/protojson/malicious-unknown-field.json",
  "crates/proto/tests/fixtures/protojson/malicious-unknown-enum.json",
  "crates/proto/tests/fixtures/protojson/malicious-wrong-shape.json",
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "vectors/README.md",
  "vectors/manifest.json",
  "vectors/wallet-key-storage-v1-golden.txt",
  "vectors/wallet-operation-v1-golden.json",
  "vectors/wallet-provider-v1-golden.txt",
  "vectors/protojson/get-credential-request.json",
  "vectors/protojson/delete-credential-success-response.json",
  "vectors/protojson/malicious-duplicate-operation.json",
  "vectors/protojson/malicious-unknown-field.json",
  "vectors/protojson/malicious-unknown-enum.json",
  "vectors/protojson/malicious-wrong-shape.json",
  "crates/http/Cargo.toml",
  "crates/http/src/lib.rs",
  "crates/http/src/serve.rs",
  "crates/http/src/serve_oidf_wallet_harness.rs",
  "crates/http/src/serve_oidf_wallet_harness_tests.rs",
  "fuzz/corpus/wallet_proto_json/get-credential-request.json",
  "fuzz/corpus/wallet_proto_json/delete-credential-success-response.json",
  "fuzz/corpus/wallet_proto_json/malicious-duplicate-operation.json",
  "fuzz/corpus/wallet_proto_json/malicious-unknown-field.json",
  "fuzz/corpus/wallet_proto_json/malicious-unknown-enum.json",
  "fuzz/corpus/wallet_proto_json/malicious-wrong-shape.json",
  ".github/workflows/protobuf-ci.yml",
  "scripts/proto-hardening/core.mjs",
  "scripts/proto-hardening/README.md",
  "scripts/check-proto-hardening-concurrency.mjs",
]) {
  requireFile(path);
}

for (const path of [
  "proto",
  "protos",
  "src",
  "tests",
  "schema-baseline",
  "crates/proto/wallet",
  "crates/proto/codec",
  "crates/ffi",
  "crates/wasm",
  "gen",
  "Package.swift",
  "Package.resolved",
  "packages",
  "crates/runtime/src/serve.rs",
  "crates/runtime/src/serve_oidf_wallet_harness.rs",
  "crates/runtime/tests/serve_tests.rs",
  "crates/runtime/examples/serve_oidf_wallet_harness.rs",
  "crates/proto/proto/reallyme/openid4vci/v1/openid4vci_service.proto",
  "crates/proto/proto/reallyme/openid4vp/v1/openid4vp_service.proto",
  "crates/types/src/delivery.rs",
  "fuzz/artifacts/wallet_delivery_json",
  "fuzz/artifacts/wallet_distribution_json",
  "fuzz/corpus/wallet_delivery_json",
  "fuzz/corpus/wallet_distribution_json",
  ".github/workflows/kotlin-jvm-ci.yml",
  ".github/workflows/wasm-binding-ci.yml",
]) {
  rejectPath(path);
}

rejectText("Cargo.toml", "connectrpc");
rejectText("Cargo.toml", "crates/ffi");
rejectText("Cargo.toml", "crates/wasm");
rejectText("crates/proto/Cargo.toml", "connectrpc");
rejectText("crates/runtime/Cargo.toml", "connectrpc");
rejectText("crates/http/Cargo.toml", "connectrpc");
rejectText("crates/runtime/Cargo.toml", "axum");
rejectText("crates/runtime/src/lib.rs", "mod serve");
requireText("Cargo.toml", '"crates/http"');
requireText("crates/wallet/Cargo.toml", 'http = ["dep:reallyme-wallet-http"]');
requireText("crates/http/Cargo.toml", 'reallyme-wallet-runtime = { path = "../runtime"');
rejectText("crates/types/Cargo.toml", "serde");
rejectText("crates/types/src/distribution.rs", "serde");
rejectText("crates/types/src/storage.rs", "serde");
rejectText("buf.gen.yaml", "protoc-gen-connect");
rejectText("buf.gen.yaml", "buf.build/apple/swift");
rejectText("buf.gen.yaml", "buf.build/protocolbuffers/java");
rejectText("buf.gen.yaml", "buf.build/protocolbuffers/kotlin");
rejectText("buf.gen.yaml", "buf.build/bufbuild/es");
requireText("buf.yaml", "path: crates/proto/proto");
requireText("buf.gen.yaml", "out: crates/proto/src/generated/buffa");
requireText("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
requireText("crates/proto-codec/Cargo.toml", 'reallyme-wallet-proto = { path = "../proto"');

rejectText(
  "crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto",
  "service WalletCoreService",
);
requireText(
  "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
  "service WalletCoreService",
);
requireText(
  "crates/proto/proto/reallyme/wallet/v1/wallet_service.proto",
  "rpc WalletOperation(WalletOperationRequest) returns (WalletOperationResponse);",
);

if (existsSync(resolve(root, "crates/proto/src/generated/connect"))) {
  failures.push("message-only Wallet proto crate must not contain generated Connect code");
}

rejectDirectJsonCalls(
  [
    "crates/attestation/src",
    "crates/consent/src",
    "crates/flows/src",
    "crates/http/src",
    "crates/inventory/src",
    "crates/keystore/src",
    "crates/lifecycle/src",
    "crates/log/src",
    "crates/provider/src",
    "crates/render/src",
    "crates/runtime/src",
    "crates/storage/src",
    "crates/types/src",
  ],
  new Set([
    // These are reviewed standards-owned JSON projections, not SDK DTOs.
    "crates/render/src/apple.rs",
    "crates/render/src/google.rs",
    "crates/render/src/build_google_wallet_jwt.rs",
    // The OIDF launch harness is a bounded conformance-only HTTP control plane.
    "crates/http/src/serve_oidf_wallet_harness.rs",
    "crates/http/src/parse_oidf_wallet_launch.rs",
    "crates/http/src/check_request_object_callbacks.rs",
    // Serializes the verified OpenID4VP Request Object only to hash its RFC 8785
    // form into the consent transcript; it never decodes or emits a DTO.
    "crates/consent/src/bind_verified_request.rs",
  ]),
);
rejectProductionMarkers(
  [
    "crates/wallet/src",
    "crates/attestation/src",
    "crates/consent/src",
    "crates/flows/src",
    "crates/http/src",
    "crates/inventory/src",
    "crates/keystore/src",
    "crates/lifecycle/src",
    "crates/log/src",
    "crates/proto-codec/src",
    "crates/provider/src",
    "crates/render/src",
    "crates/runtime/src",
    "crates/storage/src",
    "crates/types/src",
  ],
  ["#[deprecated", "allow(deprecated)", "Legacy", "legacy_", "compatibility_shim"],
);
rejectDirectJsonCalls(
  ["crates/proto-codec/src"],
  new Set(["crates/proto-codec/src/proto_json.rs"]),
);

requireText("crates/proto-codec/src/proto_json.rs", "MAX_WALLET_PROTO_JSON_BYTES");
requireText("crates/proto-codec/src/proto_json.rs", "JsonDuplicateKey");
requireText("crates/proto-codec/src/proto_json.rs", "try_encoded_len");
rejectText("crates/proto-codec/src/proto_json.rs", ".encode_to_vec()");
requireText("crates/proto-codec/src/limits.rs", "MAX_WALLET_PROTO_MESSAGE_BYTES");
requireText("crates/proto-codec/src/encode.rs", "try_encode_bounded");
rejectText("crates/proto-codec/src/encode.rs", ".encode_to_vec()");
requireText("crates/render/src/apple.rs", "MAX_PKPASS_FILE_BYTES");
requireText("crates/render/src/google.rs", "DEFAULT_MAX_GOOGLE_SAVE_URL_BYTES");
requireText("crates/http/src/serve_oidf_wallet_harness.rs", "DEFAULT_HARNESS_MAX_BODY_BYTES");
requireText("crates/http/src/parse_oidf_wallet_launch.rs", "#[serde(deny_unknown_fields)]");
requireText(
  "crates/http/src/serve_oidf_wallet_harness_tests.rs",
  "rejects_oversized_get_launch_input",
);
requireText("crates/consent/src/bind_verified_request.rs", "MAX_CONSENT_REQUEST_TRANSCRIPT_BYTES");
requireText("crates/consent/src/bind_verified_request.rs", "CONSENT_REQUEST_TRANSCRIPT_DOMAIN");
rejectText("crates/consent/src/bind_verified_request.rs", "serde_json::from_");
requireText("crates/http/src/serve.rs", "encode_wallet_operation_response");
rejectText("crates/http/src/serve.rs", ".encode_to_vec()");
requireText("crates/proto/tests/generated_security_tests.rs", "zeroize");
requireText(
  "crates/proto/tests/generated_security_tests.rs",
  "imported_protocol_owners_remain_redacted_by_wallet_snapshot_wrappers",
);
requireText(
  "crates/proto/tests/generated_security_tests.rs",
  "wallet_error_envelope_debug_redacts_nested_correlation_value",
);
requireText(
  "crates/proto/proto/reallyme/wallet/v1/errors.proto",
  "reallyme.security: sensitive-owner",
);
requireText(
  "scripts/harden-generated-wallet-proto.mjs",
  "crates/proto/proto/reallyme/wallet/v1/errors.proto",
);
requireText("scripts/harden-generated-wallet-proto.mjs", "--check-idempotent");
requireText(
  "scripts/harden-generated-wallet-proto.mjs",
  'import { hardenGeneratedProto } from "./proto-hardening/core.mjs";',
);
rejectText("scripts/harden-generated-wallet-proto.mjs", "function hardenDebug");
rejectText("scripts/harden-generated-wallet-proto.mjs", "readFileSync");
rejectText("scripts/harden-generated-wallet-proto.mjs", "writeFileSync");
requireText(
  "scripts/proto-hardening/core.mjs",
  "export function hardenGeneratedProto",
);
requireText("scripts/proto-hardening/core.mjs", "function hardenDebug");
requireText("scripts/proto-hardening/core.mjs", "function hardenDrop");
requireText("scripts/proto-hardening/core.mjs", "function hardenJsonErrors");
requireText("scripts/proto-hardening/core.mjs", "renameSync");
requireText(
  "scripts/check-proto-hardening-concurrency.mjs",
  "Promise.all([runHardener(), runHardener()])",
);
requireText("fuzz/Cargo.toml", 'name = "wallet_proto_decode"');
requireText("fuzz/Cargo.toml", 'name = "wallet_proto_json"');
requireText(
  "crates/proto-codec/tests/protojson_fixture_tests.rs",
  "protojson_fuzz_seeds_are_exact_copies_of_reviewed_contract_fixtures",
);
requireText(
  ".github/workflows/protobuf-ci.yml",
  "Check generated protobuf freshness and hardening",
);
requireText("docs/architecture/SDK_COMPOSITION.md", "reallyme/identity");
requireText(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"general_wallet_client_bindings": "reallyme/identity"',
);
requireText(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"expert_hardware_binding_provider": "injected-platform-host"',
);
requireText(
  "conformance/features/wallet-client-surface-ownership-v1.json",
  '"generic_client_substrate": "reallyme/vaultkit"',
);
requireText(
  "conformance/features/identity-wallet-handoff-v1.json",
  '"wallet_platform_binding_crates_allowed": false',
);
for (const retiredPath of [
  "docs/architecture/IDENTITY_HANDOFF.md",
  "docs/architecture/IDENTITY_SDK_HANDOFF.md",
  "docs/architecture/IDENTITY_SDK_MIGRATION_LEDGER.md",
  "conformance/features/identity-sdk-wallet-handoff-v1.json",
  "conformance/tests/identity_sdk_handoff_tests.rs",
]) {
  rejectPath(retiredPath);
}
if (failures.length !== 0) {
  console.error("proto-first boundary checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("proto-first boundary checks passed");
