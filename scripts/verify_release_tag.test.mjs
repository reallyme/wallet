// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { ReleaseTagError, verifyReleaseTag } from "./verify_release_tag.mjs";

const releaseSha = "a".repeat(40);
const env = {
  RELEASE_SHA: releaseSha,
  RELEASE_VERSION: "0.1.0",
  GITHUB_REPOSITORY: "reallyme/wallet",
  GH_TOKEN: "test-token",
};

test("absent release tag permits publication", async () => {
  const tag = await verifyReleaseTag({
    env,
    request: async () => ({ status: 404 }),
  });
  assert.equal(tag, "reallyme-wallet-v0.1.0");
});

test("existing tag at the exact commit permits retry", async () => {
  const tag = await verifyReleaseTag({
    env,
    request: async () => ({ status: 200, json: async () => ({ sha: releaseSha }) }),
  });
  assert.equal(tag, "reallyme-wallet-v0.1.0");
});

test("conflicting tag stops before publication", async () => {
  await assert.rejects(
    verifyReleaseTag({
      env,
      request: async () => ({ status: 200, json: async () => ({ sha: "b".repeat(40) }) }),
    }),
    (error) => error instanceof ReleaseTagError && error.code === "tag-conflicts-with-release-commit",
  );
});

test("lookup errors fail closed", async () => {
  await assert.rejects(
    verifyReleaseTag({ env, request: async () => ({ status: 403 }) }),
    (error) => error instanceof ReleaseTagError && error.code === "tag-lookup-failed",
  );
});
