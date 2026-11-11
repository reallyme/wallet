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
const tag = "reallyme-wallet-v0.1.0";
const annotationSha = "c".repeat(40);
const jsonResponse = (body) => ({ status: 200, json: async () => body });
const refResponse = (sha = releaseSha, type = "commit") => jsonResponse({
  ref: `refs/tags/${tag}`, object: { sha, type },
});
const lookupFailed = (error) => error instanceof ReleaseTagError && error.code === "tag-lookup-failed";

test("absent release tag permits publication", async () => {
  const result = await verifyReleaseTag({
    env,
    request: async (url, options) => {
      assert.equal(url.pathname, `/repos/reallyme/wallet/git/ref/tags/${tag}`);
      assert.equal(options.redirect, "error");
      return { status: 404 };
    },
  });
  assert.equal(result, "reallyme-wallet-v0.1.0");
});

test("existing tag at the exact commit permits retry", async () => {
  const tag = await verifyReleaseTag({
    env,
    request: async () => refResponse(),
  });
  assert.equal(tag, "reallyme-wallet-v0.1.0");
});

test("conflicting tag stops before publication", async () => {
  await assert.rejects(
    verifyReleaseTag({
      env,
      request: async () => refResponse("b".repeat(40)),
    }),
    (error) => error instanceof ReleaseTagError && error.code === "tag-conflicts-with-release-commit",
  );
});

for (const status of [302, 401, 403, 422, 429, 500]) {
  test(`HTTP ${status} fails closed rather than permitting an absent tag`, async () => {
    await assert.rejects(verifyReleaseTag({ env, request: async () => ({ status }) }), lookupFailed);
  });
}

test("annotated tags are resolved to the exact commit", async () => {
  const paths = [];
  const result = await verifyReleaseTag({
    env,
    request: async (url) => {
      paths.push(url.pathname);
      return paths.length === 1
        ? refResponse(annotationSha, "tag")
        : jsonResponse({ sha: annotationSha, object: { type: "commit", sha: releaseSha } });
    },
  });
  assert.equal(result, tag);
  assert.deepEqual(paths, [
    `/repos/reallyme/wallet/git/ref/tags/${tag}`,
    `/repos/reallyme/wallet/git/tags/${annotationSha}`,
  ]);
});

test("an annotated tag at another commit is rejected", async () => {
  let calls = 0;
  await assert.rejects(verifyReleaseTag({ env, request: async () => ++calls === 1
    ? refResponse(annotationSha, "tag")
    : jsonResponse({ sha: annotationSha, object: { type: "commit", sha: "b".repeat(40) } }),
  }), (error) => error instanceof ReleaseTagError && error.code === "tag-conflicts-with-release-commit");
});

test("a missing annotated object cannot be mistaken for an absent release tag", async () => {
  let calls = 0;
  await assert.rejects(verifyReleaseTag({ env, request: async () => ++calls === 1
    ? refResponse(annotationSha, "tag") : { status: 404 },
  }), lookupFailed);
});

test("nested annotated tags resolve without relying on ambiguous commit names", async () => {
  const nested = "d".repeat(40);
  const responses = [refResponse(annotationSha, "tag"),
    jsonResponse({ sha: annotationSha, object: { type: "tag", sha: nested } }),
    jsonResponse({ sha: nested, object: { type: "commit", sha: releaseSha } })];
  assert.equal(await verifyReleaseTag({ env, request: async () => responses.shift() }), tag);
  assert.equal(responses.length, 0);
});

test("cycles and excessive annotation depth have bounded lookups", async () => {
  for (const cycle of [false, true]) {
    let calls = 0;
    let current = annotationSha;
    await assert.rejects(verifyReleaseTag({ env, request: async () => {
      calls += 1;
      if (calls === 1) return refResponse(current, "tag");
      const next = cycle ? current : calls.toString(16).padStart(40, "0");
      const response = jsonResponse({ sha: current, object: { type: "tag", sha: next } });
      current = next;
      return response;
    } }), lookupFailed);
    assert.ok(calls <= 9);
  }
});

for (const body of [null, [], {},
  { ref: `refs/tags/${tag}-other`, object: { type: "commit", sha: releaseSha } },
  { ref: `refs/tags/${tag}`, object: { type: "tree", sha: releaseSha } },
  { ref: `refs/tags/${tag}`, object: { type: "commit", sha: "invalid" } },
]) {
  test(`malformed or non-exact reference is rejected: ${JSON.stringify(body)}`, async () => {
    await assert.rejects(verifyReleaseTag({ env, request: async () => jsonResponse(body) }), lookupFailed);
  });
}

test("network and JSON decoding failures remain typed and closed", async () => {
  const unavailable = () => Promise.reject(new ReleaseTagError("fixture-unavailable"));
  for (const request of [unavailable, async () => ({ status: 200, json: unavailable })]) {
    await assert.rejects(verifyReleaseTag({ env, request }), lookupFailed);
  }
});

test("an annotation response must identify the requested object", async () => {
  let calls = 0;
  await assert.rejects(verifyReleaseTag({ env, request: async () => ++calls === 1
    ? refResponse(annotationSha, "tag")
    : jsonResponse({ sha: "d".repeat(40), object: { type: "commit", sha: releaseSha } }),
  }), lookupFailed);
});
