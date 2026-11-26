// Deterministic mutation harness for the real wasm workbench.
// Usage: node scripts/mutation_check.mjs [iterations]
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRuntime } from "../web/runtime.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const iterations = Number(process.argv[2] || 10000);
const wasm = new WebAssembly.Module(readFileSync(resolve(root, "_build/wasm/release/build/src/web/web.wasm")));
const runtime = createRuntime(wasm);
const sample = readFileSync(resolve(root, "examples/dbg.exe")).subarray(0, 4096);

let seed = 0x6d6f6f6e;
function rnd() {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed;
}

let failures = 0;
for (let i = 0; i < iterations; i++) {
  const mode = rnd() % 3;
  let bytes;
  if (mode === 0) {
    bytes = sample.slice(0, rnd() % (sample.length + 1));
  } else {
    bytes = sample.slice();
    const flips = 1 + (rnd() % 8);
    for (let j = 0; j < flips; j++) {
      const at = rnd() % bytes.length;
      bytes[at] ^= 1 << (rnd() % 8);
    }
  }
  try {
    const result = runtime.run(bytes, ["moonforge-web-v2", "input.bin"]);
    const parsed = JSON.parse(result.stdout);
    if (parsed.protocol !== "moonforge-v2") throw new Error("missing protocol marker");
  } catch (error) {
    failures++;
    if (failures <= 5) console.error(`[FAIL] iteration ${i}: ${error.message}`);
  }
}

console.log(`mutation harness: ${iterations} inputs, ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
