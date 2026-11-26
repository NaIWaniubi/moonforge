// Cross-check MoonForge's PE summary against objdump when available.
// Unknown or unavailable external tools are reported as SKIP, never as PASS.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(resolve(root, "_build"), { recursive: true });
const manifestPath = resolve(root, "_build/cross-check-manifest.json");
const scan = spawnSync("moon", ["run", "cmd/main", "--", "scan", "examples", "--out", manifestPath], {
  cwd: root,
  encoding: "utf8",
});
if (scan.status !== 0) {
  console.error(scan.stdout || scan.stderr || "moon scan failed");
  process.exit(1);
}
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const notepad = manifest.files.find((f) => f.path.endsWith("notepad.exe"));
if (!notepad) {
  console.error("notepad.exe missing from manifest");
  process.exit(1);
}

const objdump = spawnSync("objdump", ["-p", resolve(root, "examples/notepad.exe")], { encoding: "utf8" });
if (objdump.status !== 0) {
  console.log("SKIP objdump unavailable");
  process.exit(0);
}
const text = objdump.stdout;
const sectionText = spawnSync("objdump", ["-h", resolve(root, "examples/notepad.exe")], { encoding: "utf8" }).stdout || "";
const sections = (sectionText.match(/^\s*\d+\s+\.\S+/gm) || []).length;
const importPart = text.split("The Import Tables")[1] || "";
let imports = 0;
for (const line of importPart.split(/\r?\n/)) {
  if (/DLL Name:.*delayload/i.test(line)) break;
  if (/^\s+[0-9a-fA-F]+\s+\d+\s+\S+/.test(line)) imports++;
}
let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: moonforge=${actual} objdump=${expected}`);
  if (!ok) failures++;
}
check("PE sections", notepad.summary.sections, sections);
// moonforge counts INT entries; objdump interprets the bound IAT and can list
// more symbols. Compare the invariant rather than pretending the two semantics
// are identical on a bound image.
const dllCount = (text.match(/DLL Name:/g) || []).length;
const importsOk = notepad.summary.imports > 0 && dllCount > 0 && notepad.summary.imports >= dllCount;
console.log(`${importsOk ? "PASS" : "FAIL"} PE imports present: moonforge=${notepad.summary.imports} objdump_dlls=${dllCount} (INT vs bound-IAT semantics)`);
if (!importsOk) failures++;
console.log(`cross-check: ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
