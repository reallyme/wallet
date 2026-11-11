#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const WALLET_PACKAGE = "reallyme.wallet.v1";
const BASELINE = "crates/proto/baselines/wallet-v1.binpb";

const fail = (message) => {
  process.stderr.write(`Wallet schema breaking check failed: ${message}\n`);
  process.exit(1);
};

const runBuf = (arguments_) => {
  const result = spawnSync("buf", arguments_, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    fail("buf could not be executed");
  }
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim();
    fail(detail || "buf returned a nonzero status");
  }
};

const temporaryDirectory = mkdtempSync(join(tmpdir(), "reallyme-wallet-breaking-"));
const currentImage = join(temporaryDirectory, "current.binpb");
const baselineImage = join(temporaryDirectory, "baseline.binpb");

try {
  // Keep imported descriptors for type resolution, but apply compatibility
  // checks only to Wallet-owned files. Registry-owned schema evolution is
  // checked against the resolved crate sources by the source-lock gate.
  runBuf(["build", "--type", WALLET_PACKAGE, "-o", currentImage]);
  runBuf(["build", BASELINE, "--type", WALLET_PACKAGE, "-o", baselineImage]);
  runBuf([
    "breaking", currentImage, "--against", baselineImage,
    "--exclude-imports", "--path", "reallyme/wallet/v1",
  ]);
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}

process.stdout.write("Wallet-owned schema is compatible with the locked v1 baseline\n");
