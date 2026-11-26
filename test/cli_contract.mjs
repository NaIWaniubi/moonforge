// CLI machine-contract checks: stdout is JSON, stderr is for humans, exit
// codes are stable. Usage: node test/cli_contract.mjs
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const diff = resolve(root, "_build/native/debug/build/cmd/diff/diff.exe");
const gate = resolve(root, "_build/native/debug/build/cmd/gate/gate.exe");
const oldFacts = resolve(root, "fixtures_breadth/old-facts.json");
const newFacts = resolve(root, "fixtures_breadth/new-facts.json");
const policy = resolve(root, "fixtures_breadth/policy.json");

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " -> " + detail : ""}`);
  if (!ok) failures++;
}

const d = spawnSync(diff, [oldFacts, newFacts], { encoding: "utf8" });
let dj;
try { dj = JSON.parse(d.stdout); } catch {}
check("diff exits 0", d.status === 0, String(d.status));
check("diff stdout is canonical JSON", !!dj && Array.isArray(dj.added) && Array.isArray(dj.removed) && Array.isArray(dj.changed));
check("diff detects seeded added fact", dj?.added?.some((x) => x.key === "kernel32!NewApi"));

const s = spawnSync(diff, [oldFacts, newFacts, "--format", "sarif"], { encoding: "utf8" });
let sj;
try { sj = JSON.parse(s.stdout); } catch {}
check("diff SARIF exits 0", s.status === 0, String(s.status));
check("SARIF version is 2.1.0", sj?.version === "2.1.0");
check("SARIF has one run", Array.isArray(sj?.runs) && sj.runs.length === 1);

const g = spawnSync(gate, [oldFacts, newFacts, policy], { encoding: "utf8" });
let gj;
try { gj = JSON.parse(g.stdout); } catch {}
check("gate exits 1 on policy violation", g.status === 1, String(g.status));
check("gate stdout is JSON", !!gj && gj.passed === false);
check("gate reports the matching rule", gj?.violations?.[0]?.rule_id === "no-new-kernel32-import");

console.log(`CLI contract: ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
