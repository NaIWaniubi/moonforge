// Reproducible in-memory corpus benchmark for the wasm workbench.
// Usage: node bench/run_bench.mjs [files]
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRuntime } from "../web/runtime.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const count = Number(process.argv[2] || 1000);
const p95LimitMs = Number(process.env.MOONFORGE_BENCH_P95_MS || 150);
if (!Number.isInteger(count) || count < 2) throw new Error("files must be an integer >= 2");
if (!Number.isFinite(p95LimitMs) || p95LimitMs <= 0) throw new Error("MOONFORGE_BENCH_P95_MS must be positive");
const wasm = new WebAssembly.Module(readFileSync(resolve(root, "_build/wasm/release/build/src/web/web.wasm")));
const runtime = createRuntime(wasm);
const seed = readFileSync(resolve(root, "examples/dbg.exe")).subarray(0, 2048);
const files = {};
for (let i = 0; i < count; i++) files[`sample-${i}.bin`] = seed;
const names = Object.keys(files);
const argv = ["moonforge-web-v2", names[0], names[1]];

const times = [];
for (let i = 0; i < 20; i++) {
  const start = performance.now();
  const result = runtime.run(files, argv);
  const elapsed = performance.now() - start;
  if (result.exitCode !== null && result.exitCode !== 0) {
    throw new Error("workbench exited with code " + result.exitCode + ": " + result.stderr.slice(0, 200));
  }
  JSON.parse(result.stdout);
  times.push(elapsed);
}
times.sort((a, b) => a - b);
const p50 = times[Math.floor(times.length * 0.5)];
const p95 = times[Math.floor(times.length * 0.95)];
const passed = p95 <= p95LimitMs;
console.log(JSON.stringify({
  files: count,
  runs: times.length,
  p50_ms: Number(p50.toFixed(2)),
  p95_ms: Number(p95.toFixed(2)),
  p95_limit_ms: p95LimitMs,
  passed,
}));
if (!passed) process.exit(1);
