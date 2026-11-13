// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./prepare_eudi_release_inputs.mjs", import.meta.url));
const policy = JSON.parse(readFileSync(new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url), "utf8"));
const sha = "a".repeat(40);
const frameworkSha = "b".repeat(40);

const fixture = (scenario = "success", targetMode = "published", overrides = {}) => {
  const targetPolicy = { ...policy, release_version: scenario === "historical-candidate" ? "0.1.1" : policy.release_version };
  const root = mkdtempSync(join(tmpdir(), "wallet-eudi-input-test-"));
  try {
    const framework = join(root, "framework");
    mkdirSync(join(framework, "upstream/eudi"), { recursive: true });
    mkdirSync(join(framework, "references"));
    for (const path of ["upstream/eudi/sources.lock.json", "upstream/eudi/legal-sources.lock.json", "references/eudi-publications.lock.json"]) {
      writeFileSync(join(framework, path), "{}\n");
    }
    const archives = policy.authorized_public_packages.map((name) => {
      const bytes = Buffer.from(`fixture archive:${name}`);
      return { file: `${name}-${targetPolicy.release_version}.crate`, size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    }).sort((a, b) => a.file.localeCompare(b.file));
    const manifest = { schema: "reallyme.wallet.crates_preflight.v3", crates: archives,
      prerequisites: { fuzz: 1, protobuf_ci: 2, rust_ci: 3 }, repository: "reallyme/wallet",
      workflow: "crates-package-preflight.yml", run_id: 42, run_attempt: 1, release_sha: sha, version: targetPolicy.release_version };
    const toolchainSource = readFileSync(new URL("../rust-toolchain.toml", import.meta.url), "utf8");
    const preflightSource = readFileSync(new URL("../.github/workflows/crates-package-preflight.yml", import.meta.url), "utf8");
    const calls = join(root, "calls.json");
    const preload = join(root, "preload.mjs");
    writeFileSync(preload, `
import cp from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
const scenario = ${JSON.stringify(scenario)};
const targetMode = ${JSON.stringify(targetMode)};
const manifest = ${JSON.stringify(manifest)};
const sha = ${JSON.stringify(sha)};
const framework = ${JSON.stringify(frameworkSha)};
const toolchainSource = ${JSON.stringify(toolchainSource)};
const preflightSource = ${JSON.stringify(preflightSource)};
const policySource = ${JSON.stringify(JSON.stringify(targetPolicy))};
const calls = [];
const ok = {status:0,stdout:"",stderr:""};
const answer = (value) => ({...ok,stdout:JSON.stringify(value)});
const realSpawnSync = cp.spawnSync.bind(cp);
cp.spawnSync = (program,args,options) => {
  if(program === "tar" && options?.env?.COPYFILE_DISABLE !== "1") return {...ok,status:98};
  calls.push([program,...args]);
  writeFileSync(${JSON.stringify(calls)},JSON.stringify(calls));
  if(program === "git") return {...ok,stdout: args.includes("rev-parse") ? framework : scenario === "dirty-framework" ? " M changed" : ""};
  if(program === "tar") {
    if(scenario === "archive-members") {
      if(process.platform === "darwin") {
        const metadata=realSpawnSync("xattr",["-w","user.wallet_bundle_test","public-fixture",join(args[args.indexOf("-C")+1],manifest.crates[0].file)],{encoding:"utf8"});
        if(metadata.status !== 0) return metadata;
      }
      return realSpawnSync(program,args,options);
    }
    writeFileSync(args[1],"fixture bundle"); return ok;
  }
  if(program === "python3") return ok;
  if(program !== "gh") return {...ok,status:99};
  if(args[0] === "attestation") return scenario === "signature-failure" ? {...ok,status:1} : ok;
  if(args[0] === "release" || args[0] === "run") {
    const directory=args[args.indexOf("--dir")+1];
    const requestedName=args[args.indexOf("--name")+1];
    if(args[0] === "release" || requestedName?.startsWith("reallyme-wallet-crate-archives-")) {
      for(const item of manifest.crates) {
        const name=item.file.slice(0,-"-${targetPolicy.release_version}.crate".length);
        writeFileSync(join(directory,item.file),scenario === "tampered-archive" ? "tampered" : "fixture archive:"+name);
      }
    }
    if(args[0] === "release" || requestedName?.startsWith("reallyme-wallet-crates-preflight-")) {
      writeFileSync(join(directory,"crates-preflight.json"),JSON.stringify(manifest));
    }
    return ok;
  }
  const endpoint=args[1];
  if(endpoint.includes("releases/tags/")) return answer({id:1,tag_name:"reallyme-wallet-v${targetPolicy.release_version}",draft:scenario==="draft-release",prerelease:false});
  if(endpoint.includes("actions/workflows/") && endpoint.includes("/runs?")) return answer({workflow_runs:[{id:42,workflow_id:5,display_title:"Crates package preflight ${targetPolicy.release_version} @ "+sha,event:"workflow_dispatch",head_branch:"main",head_sha:sha,path:".github/workflows/crates-package-preflight.yml",status:"completed",conclusion:"success",run_attempt:1}]});
  if(endpoint.includes("actions/workflows")) return answer({id:5});
  if(endpoint.includes("/jobs?")) return answer({total_count:1,jobs:[{id:9,run_id:42,run_attempt:1,head_sha:sha,name:"Review crates.io packages",status:"completed",conclusion:"success",steps:["Check formatting","Clippy","Test all features","Check protobuf boundaries and generated source","Check dependency policy","Security advisory audit","Inspect normalized crate tarballs and dry-run publication","Check Identity Wasm participant lane"].map((name,index)=>({name,number:index+1,status:"completed",conclusion:scenario==="failed-step" && index===0 ? "failure":"success"}))}]});
  if(endpoint.includes("actions/runs")) return answer({id:42,workflow_id:5,event:"workflow_dispatch",head_branch:"main",head_sha:scenario==="wrong-preflight-commit" ? "f".repeat(40):sha,status:"completed",conclusion:"success",run_attempt:1,path:".github/workflows/crates-package-preflight.yml"});
  if(endpoint.includes("/compare/")) return answer({status:scenario === "non-main-candidate" ? "diverged" : "ahead",merge_base_commit:{sha:scenario === "wrong-ancestor" ? "f".repeat(40):sha}});
  if(endpoint.includes("git/ref/heads/main")) return answer({object:{sha}});
  if(endpoint.includes("contents/conformance/features/wallet-package-policy-v1.json")) return answer({encoding:"base64",content:Buffer.from(policySource).toString("base64"),size:Buffer.byteLength(policySource)});
  if(endpoint.includes("contents/rust-toolchain.toml")) {
    const text=scenario==="historical-toolchain" ? toolchainSource.replaceAll("1.100.0","1.99.0") : scenario==="floating-toolchain" ? toolchainSource.replace("1.100.0","stable") : toolchainSource;
    const source={encoding:"base64",content:Buffer.from(text).toString("base64"),size:Buffer.byteLength(text)};
    if(scenario==="invalid-source-encoding") source.content+="!";
    if(scenario==="invalid-source-size") source.size+=1;
    if(scenario==="oversized-source") source.content="A".repeat(32_769);
    if(scenario==="invalid-source-object") return answer([]);
    return answer(source);
  }
  if(endpoint.includes("contents/.github/workflows/crates-package-preflight.yml")) {
    const text=scenario==="historical-toolchain" || scenario==="mismatched-toolchain" ? preflightSource.replaceAll("1.100.0","1.99.0") : preflightSource;
    return answer({encoding:"base64",content:Buffer.from(text).toString("base64"),size:Buffer.byteLength(text)});
  }
  if(endpoint.includes("contents/Cargo.lock")) return answer({encoding:"base64",content:Buffer.from("fixture cargo lock").toString("base64")+(scenario==="invalid-lock-encoding" ? "!":""),size:18});
  return {...ok,status:99};
};
globalThis.fetch = async (url) => {
  if(targetMode === "candidate") throw new Error("candidate mode performed a publication lookup");
  const target=String(url);
  if(target.startsWith("https://api.github.com/")) return new Response(JSON.stringify({ref:"refs/tags/reallyme-wallet-v${targetPolicy.release_version}",object:{type:"commit",sha:scenario==="wrong-tag" ? "f".repeat(40):sha}}));
  const name=target.split("/").at(-2);
  const archive=manifest.crates.find(item=>item.file===name+"-${targetPolicy.release_version}.crate");
  return new Response(JSON.stringify({version:{crate:name,num:"${targetPolicy.release_version}",yanked:scenario==="yanked",checksum:scenario==="registry-mismatch" ? "0".repeat(64):archive.sha256}}));
};
syncBuiltinESMExports();
`);
    const output = join(root, "inputs");
    const githubOutput = join(root, "github-output");
    const completed = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script], {
      encoding: "utf8", timeout: 15_000, env: { ...process.env,
        GITHUB_REPOSITORY: "reallyme/wallet", GH_TOKEN: "fixture-only-not-a-credential",
        GITHUB_SHA: sha, TARGET_MODE: targetMode,
        EUDI_TARGET_COMMIT: targetMode === "candidate" ? sha : "",
        PREFLIGHT_RUN_ID: targetMode === "candidate" ? "42" : "",
        EUDI_WALLET_RELEASE: targetMode === "published" ? `reallyme-wallet-v${targetPolicy.release_version}` : "", EUDI_WRITE_GITHUB_OUTPUT: "1", GITHUB_OUTPUT: githubOutput,
        RUNNER_TEMP: root, FRAMEWORK_COMMIT: frameworkSha, EUDI_FRAMEWORK_PATH: framework, EUDI_INPUT_DIRECTORY: output, ...overrides,
      },
    });
    assert.equal(completed.error, undefined);
    let archiveMembers;
    let archiveTypes;
    if (scenario === "archive-members" && completed.status === 0) {
      const bundle = join(output, "wallet-release");
      const names = spawnSync("tar", ["-tf", bundle], { encoding: "utf8", timeout: 15_000 });
      const entries = spawnSync("tar", ["-tvf", bundle], { encoding: "utf8", timeout: 15_000 });
      assert.equal(names.status, 0, names.stderr);
      assert.equal(entries.status, 0, entries.stderr);
      archiveMembers = names.stdout.trim().split("\n");
      archiveTypes = entries.stdout.trim().split("\n").map((line) => line[0]);
    }
    return { ...completed, calls: existsSync(calls) ? JSON.parse(readFileSync(calls, "utf8")) : [],
      archiveMembers, archiveTypes,
      deployment: existsSync(join(output, "deployment.json")) ? JSON.parse(readFileSync(join(output, "deployment.json"), "utf8")) : undefined,
      attestation: existsSync(join(output, "wallet-attestation.json")) ? JSON.parse(readFileSync(join(output, "wallet-attestation.json"), "utf8")) : undefined,
      githubOutput: existsSync(githubOutput) ? readFileSync(githubOutput, "utf8") : undefined };
  } finally { rmSync(root, { recursive: true, force: true }); }
};

test("hosted input preparation verifies all 18 signatures before binding real CI evidence", () => {
  const result = fixture();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.filter((call) => call[0] === "gh" && call[1] === "attestation").length, 18);
  assert.equal(result.deployment.component.commit, sha);
  assert.deepEqual(result.deployment.component, {
    component_id: "wallet", repository: "https://github.com/reallyme/wallet", commit: sha,
  });
  assert.deepEqual(result.deployment.target, result.attestation.target);
  assert.deepEqual(result.deployment.target, {
    mode: "published", version: policy.release_version, commit: sha, preflight_run_id: 42,
    release_id: 1, release_ref: `reallyme-wallet-v${policy.release_version}`,
  });
  assert.match(result.githubOutput, /^target_mode=published$/mu);
  assert.match(result.githubOutput, /^release_id=1$/mu);
  assert.match(result.githubOutput, new RegExp(`^release_ref=reallyme-wallet-v${policy.release_version.replaceAll(".", "\\.")}$`, "mu"));
  assert.equal(result.attestation.checks.length, 7);
  assert.equal(result.attestation.target.version, policy.release_version);
  assert.deepEqual(result.attestation.toolchain, { identifier: "rust", version: "1.100.0" });
  assert.equal(result.calls.some((call) => call[0] === "cargo"), false);
  assert.ok(result.calls.findIndex((call) => call[1] === "attestation") < result.calls.findIndex((call) => call[0] === "tar"));
});

test("native tar emits exactly the reviewed regular members without metadata sidecars", () => {
  const expectedMembers = ["crates-preflight.json",
    ...policy.authorized_public_packages.map((name) => `${name}-${policy.release_version}.crate`),
    ...["format", "lint", "unit", "integration", "vector", "security", "build"]
      .map((category) => `evidence-${category}.json`)].sort();
  for (const mode of ["candidate", "published"]) {
    const result = fixture("archive-members", mode);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.archiveMembers.sort(), expectedMembers);
    assert.equal(result.archiveTypes.length, expectedMembers.length);
    assert.ok(result.archiveTypes.every((type) => type === "-"));
  }
});

test("candidate mode consumes only the exact current commit preflight", () => {
  const result = fixture("success", "candidate");
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.deployment.target, {
    mode: "candidate", version: policy.release_version, commit: sha, preflight_run_id: 42,
  });
  assert.deepEqual(result.attestation.target, result.deployment.target);
  assert.match(result.githubOutput, /^target_mode=candidate$/mu);
  assert.match(result.githubOutput, /^release_id=$/mu);
  assert.match(result.githubOutput, /^release_ref=$/mu);
  assert.equal(result.calls.some((call) => call[0] === "gh" && call[1] === "release"), false);
  assert.equal(result.calls.filter((call) => call[0] === "gh" && call[1] === "run").length, 2);
  assert.equal(result.calls.filter((call) => call[0] === "gh" && call[1] === "attestation").length, 18);
});

test("historical candidate retests reuse the selected signed preflight and target package version", () => {
  const result = fixture("historical-candidate", "candidate", {
    GITHUB_SHA: "f".repeat(40), EUDI_TARGET_COMMIT: sha, PREFLIGHT_RUN_ID: "42",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.deployment.target, { mode: "candidate", version: "0.1.1", commit: sha, preflight_run_id: 42 });
  assert.ok(result.calls.some((call) => call[2] === `repos/reallyme/wallet/compare/${sha}...main`));
  assert.ok(result.calls.some((call) => call[2] === `repos/reallyme/wallet/contents/conformance/features/wallet-package-policy-v1.json?ref=${sha}`));
  assert.equal(result.calls.some((call) => call[2]?.includes("/runs?")), false);
});

for (const scenario of ["non-main-candidate", "wrong-ancestor"]) {
  test(`${scenario} is refused despite a successful preflight`, () => {
    const result = fixture(scenario, "candidate", { EUDI_TARGET_COMMIT: sha, PREFLIGHT_RUN_ID: "42" });
    assert.equal(result.status, 1);
    assert.equal(result.deployment, undefined);
    assert.match(result.stderr, /candidate_is_not_main_ancestor/u);
  });
}

for (const preflight of ["0", "-1", "4\n2", "9007199254740992", "43"]) {
  test(`candidate rejects invalid or substituted explicit preflight ${JSON.stringify(preflight)}`, () => {
    const result = fixture("success", "candidate", { PREFLIGHT_RUN_ID: preflight });
    assert.equal(result.status, 1);
    assert.equal(result.deployment, undefined);
  });
}

test("published mode refuses candidate overrides", () => {
  for (const overrides of [{ EUDI_TARGET_COMMIT: sha }, { PREFLIGHT_RUN_ID: "42" }]) {
    const result = fixture("success", "published", overrides);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /published_target_override/u);
  }
});

test("candidate requires an exact target and evidence run and refuses published identity", () => {
  for (const overrides of [{ EUDI_TARGET_COMMIT: "" }, { EUDI_TARGET_COMMIT: "main" },
    { PREFLIGHT_RUN_ID: "" }, { EUDI_WALLET_RELEASE: `reallyme-wallet-v${policy.release_version}` }]) {
    const result = fixture("success", "candidate", overrides);
    assert.equal(result.status, 1);
    assert.equal(result.deployment, undefined);
  }
});

test("published mode requires a valid explicit release tag", () => {
  for (const reference of ["", "latest", "reallyme-wallet-v01.2.3", "reallyme-wallet-v0.1.2\n"]) {
    const result = fixture("success", "published", { EUDI_WALLET_RELEASE: reference });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /invalid_published_release_selection/u);
  }
});

for (const scenario of ["draft-release", "dirty-framework", "tampered-archive", "signature-failure",
  "wrong-preflight-commit", "failed-step", "wrong-tag", "yanked", "registry-mismatch", "invalid-lock-encoding",
  "floating-toolchain", "mismatched-toolchain", "invalid-source-encoding", "invalid-source-size",
  "oversized-source", "invalid-source-object"]) {
  test(`${scenario} fails before creating deployment evidence`, () => {
    const result = fixture(scenario);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.deployment, undefined);
    assert.equal(result.attestation, undefined);
    assert.equal(result.calls.some((call) => call[0] === "tar"), false);
    assert.doesNotMatch(result.stderr, /fixture-only-not-a-credential/u);
  });
}

test("historical release evidence retains its actual compiler under a newer caller", () => {
  const result = fixture("historical-toolchain");
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.attestation.toolchain, { identifier: "rust", version: "1.99.0" });
  assert.ok(result.calls.some(call => call[0] === "gh" && call[1] === "api" &&
    call[2] === `repos/reallyme/wallet/contents/rust-toolchain.toml?ref=${sha}`));
  assert.ok(result.calls.some(call => call[0] === "gh" && call[1] === "api" &&
    call[2] === `repos/reallyme/wallet/contents/.github/workflows/crates-package-preflight.yml?ref=${sha}`));
});
