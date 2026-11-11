#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const wrapper = resolve(root, "scripts/harden-generated-wallet-proto.mjs");
const generatedRoot = resolve(root, "crates/proto/src/generated/buffa");
const generatedPaths = [
  resolve(generatedRoot, "reallyme.wallet.v1.wallet_policy.rs"),
  resolve(generatedRoot, "reallyme.wallet.v1.errors.rs"),
  resolve(generatedRoot, "reallyme.wallet.v1.wallet.rs"),
  resolve(generatedRoot, "reallyme.wallet.v1.wallet_operation.rs"),
  resolve(generatedRoot, "reallyme.wallet.v1.wallet_provider.rs"),
];

function fail(message) {
  console.error(`generated Wallet protobuf concurrency check failed: ${message}`);
  process.exit(1);
}

if (process.argv.length !== 2) {
  fail("arguments are not supported");
}

const before = new Map(
  generatedPaths.map((path) => [path, readFileSync(path)]),
);

function runHardener() {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [wrapper, "--check-idempotent"], {
      cwd: root,
      stdio: "ignore",
    });
    child.once("error", () => resolveRun(false));
    child.once("exit", (code) => resolveRun(code === 0));
  });
}

const results = await Promise.all([runHardener(), runHardener()]);
if (results.some((result) => !result)) {
  fail("a concurrent hardener process failed");
}

for (const [path, original] of before) {
  if (!original.equals(readFileSync(path))) {
    fail("concurrent hardening changed generated output");
  }
}

console.log("generated Wallet protobuf hardening is concurrency-safe");
