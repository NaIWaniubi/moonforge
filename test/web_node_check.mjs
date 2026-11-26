// Node acceptance test for the moonforge wasm workbench.
//
// It loads the real web.wasm through the same runtime the page uses, feeds it
// examples/notepad.exe, and asserts the JSON the MoonBit code emits. A failure
// here means the workbench is broken in the browser too — this is the gate,
// not a smoke test that passes on an empty page.
//
// Usage: node test/web_node_check.mjs [path-to-exe]

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRuntime } from "../web/runtime.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wasmPath = resolve(root, "_build/wasm/release/build/src/web/web.wasm");
const samplePath = process.argv[2] ?? resolve(root, "examples/notepad.exe");

const module = new WebAssembly.Module(readFileSync(wasmPath));
const runtime = createRuntime(module);
const sample = readFileSync(samplePath);

let failures = 0;
function check(name, ok, detail) {
  if (ok) {
    console.log("  [PASS] " + name + (detail ? " -> " + detail : ""));
  } else {
    failures += 1;
    console.log("  [FAIL] " + name + (detail ? " -> " + detail : ""));
  }
}

console.log("moonforge wasm workbench");
console.log("  wasm  " + readFileSync(wasmPath).length + " bytes");
console.log("  input " + samplePath + " (" + sample.length + " bytes)");

// 1. Structure + xref on a real PE.
const r1 = runtime.run(sample, ["moonforge-web", "input.bin"]);
const j1 = JSON.parse(r1.stdout);
check("format detected as pe", j1.format === "pe", j1.format);
check("size matches the file", j1.size === sample.length, String(j1.size));
check("sections parsed", j1.sections === 7, String(j1.sections));
check("imports parsed", j1.imports === 315, String(j1.imports));
check("sha256 present (64 hex chars)", typeof j1.sha256 === "string" && j1.sha256.length === 64, j1.sha256.slice(0, 12) + "…");
check("xref block present for PE", j1.xref !== null && typeof j1.xref === "object");
check("xref slot count", j1.xref && j1.xref.slots === 340, j1.xref && String(j1.xref.slots));
check("xref resolved sites > 1000", j1.xref && j1.xref.sites > 1000, j1.xref && String(j1.xref.sites));
check(
  "top API list is non-empty",
  Array.isArray(j1.xref && j1.xref.top) && j1.xref.top.length > 0,
  j1.xref && j1.xref.top.slice(0, 3).map((a) => a.api + ":" + a.count).join(" "),
);

// 2. Text is extracted from the binary.
check("extracted text is substantial", j1.text_bytes > 1000, String(j1.text_bytes));

// 3. Search across the file's own text.
const r2 = runtime.run(sample, ["moonforge-web", "input.bin", "HeapAlloc"]);
const j2 = JSON.parse(r2.stdout);
check("search returned a match", Array.isArray(j2.matches) && j2.matches.length > 0, String(j2.matches && j2.matches.length));
check(
  "match carries a snippet with context",
  j2.matches && j2.matches.length > 0 && typeof j2.matches[0].snippet === "string" && j2.matches[0].snippet.length > 0,
  j2.matches && j2.matches[0] && j2.matches[0].snippet.slice(0, 48),
);

// 4. A non-PE input must not fabricate an xref block.
const textBytes = new TextEncoder().encode("hello moonforge\nVirtualAlloc here\n");
const r3 = runtime.run(textBytes, ["moonforge-web", "input.bin", "VirtualAlloc"]);
const j3 = JSON.parse(r3.stdout);
check("non-PE format is unknown", j3.format === "unknown", j3.format);
check("non-PE has no xref block", j3.xref === null, String(j3.xref));
check("non-PE text still searchable", j3.matches && j3.matches.length === 1, String(j3.matches && j3.matches.length));

// 5. v2 multi-artifact protocol: real PE + plist + WASM in one run.
const plistBytes = readFileSync(resolve(root, "fixtures_breadth/Info.plist"));
const wasmBytes = readFileSync(resolve(root, "fixtures_breadth/minimal.wasm"));
const r4 = runtime.run(
  { "dbg.exe": sample, "Info.plist": plistBytes, "minimal.wasm": wasmBytes },
  ["moonforge-web-v2", "dbg.exe", "Info.plist", "minimal.wasm", "--query", "Bundle"],
);
const j4 = JSON.parse(r4.stdout);
check("v2 protocol marker", j4.protocol === "moonforge-v2", j4.protocol);
check("v2 returns every artifact", Array.isArray(j4.artifacts) && j4.artifacts.length === 3, String(j4.artifacts?.length));
check("v2 PE carries xref v2 ledger", j4.artifacts?.[0]?.xref_v2?.ledger?.decoded_calls > 0, String(j4.artifacts?.[0]?.xref_v2?.ledger?.decoded_calls));
check("v2 WASM artifact carries section report", Array.isArray(j4.artifacts?.[2]?.wasm), String(j4.artifacts?.[2]?.wasm?.length));
check("v2 two artifacts produce a diff", j4.diff && typeof j4.diff === "object");
check("v2 search spans artifacts", Array.isArray(j4.matches));
check(
  "v2 reports honest read and parse status",
  j4.artifacts?.every((a) => a.read_status === "ok" && a.parse_status === "parsed"),
  j4.artifacts?.map((a) => a.read_status + "/" + a.parse_status).join(","),
);

const policyText = JSON.stringify({ rules: [{ id: "no-format-change", kind: "artifact", change: "changed", key_prefix: "format" }] });
const r5 = runtime.run(
  { "dbg.exe": sample, "Info.plist": plistBytes },
  ["moonforge-web-v2", "dbg.exe", "Info.plist", "--policy", policyText],
);
const j5 = JSON.parse(r5.stdout);
check("v2 policy gate blocks a seeded change", j5.gate?.passed === false && j5.gate?.violations?.[0]?.rule_id === "no-format-change");
check("v2 invalid policy fails closed", (() => {
  const bad = runtime.run(
    { "dbg.exe": sample, "Info.plist": plistBytes },
    ["moonforge-web-v2", "dbg.exe", "Info.plist", "--policy", "{\"rules\":[{\"kind\":\"import\"}]}"],
  );
  const parsed = JSON.parse(bad.stdout);
  return parsed.gate?.passed === false && typeof parsed.gate?.error === "string";
})());

console.log(failures === 0 ? "\nWASM WORKBENCH PASS" : "\nWASM WORKBENCH FAIL (" + failures + ")");
process.exit(failures === 0 ? 0 : 1);