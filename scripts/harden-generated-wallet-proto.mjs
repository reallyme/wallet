#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { hardenGeneratedProto } from "./proto-hardening/core.mjs";

const supportedArguments = new Set(["--check-idempotent"]);
const suppliedArguments = new Set();

function fail(message) {
  console.error(`generated Wallet protobuf hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const generatedRoot = resolve(root, "crates/proto/src/generated/buffa");

hardenGeneratedProto({
  checkIdempotent: suppliedArguments.has("--check-idempotent"),
  contracts: [
    {
      proto: resolve(root, "crates/proto/proto/reallyme/wallet/v1/wallet_policy.proto"),
      owned: resolve(generatedRoot, "reallyme.wallet.v1.wallet_policy.rs"),
    },
    {
      proto: resolve(
        root,
        "crates/proto/proto/reallyme/wallet/v1/wallet.proto",
      ),
      owned: resolve(generatedRoot, "reallyme.wallet.v1.wallet.rs"),
    },
    {
      proto: resolve(
        root,
        "crates/proto/proto/reallyme/wallet/v1/wallet_key_storage.proto",
      ),
      owned: resolve(
        generatedRoot,
        "reallyme.wallet.v1.wallet_key_storage.rs",
      ),
    },
    {
      proto: resolve(
        root,
        "crates/proto/proto/reallyme/wallet/v1/wallet_operation.proto",
      ),
      owned: resolve(
        generatedRoot,
        "reallyme.wallet.v1.wallet_operation.rs",
      ),
    },
    {
      proto: resolve(
        root,
        "crates/proto/proto/reallyme/wallet/v1/wallet_provider.proto",
      ),
      owned: resolve(
        generatedRoot,
        "reallyme.wallet.v1.wallet_provider.rs",
      ),
    },
    {
      proto: resolve(
        root,
        "crates/proto/proto/reallyme/wallet/v1/errors.proto",
      ),
      owned: resolve(generatedRoot, "reallyme.wallet.v1.errors.rs"),
    },
  ],
  failurePrefix: "generated Wallet protobuf hardening failed",
  sensitiveOneofs: [
    {
      path: resolve(generatedRoot, "reallyme.wallet.v1.wallet_key_storage.__oneof.rs"),
      enumName: "Binding",
      byteVariants: ["WscdOpaqueHandle"],
    },
  ],
});
