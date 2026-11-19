# moonforge

**A pure-MoonBit workbench that turns five ecosystem tools into one reverse-engineering flow.**
Scan a directory of binaries, cross-reference imported APIs against their call sites, and search every string inside them — from one CLI or one browser tab.

Other ecosystems have this: `goblin`/`LIEF` for containers, `capstone` for disassembly, plus a shell to glue them. MoonBit now has the pieces (moonbin, moonpe, moonseek, moonplist, moonbit-wasm-inspect) — but no single place that composes them and adds the join nobody provides. moonforge is that place. Zero FFI; the same source builds to native and to wasm.

## Three flows

```bash
# 1. inventory a corpus: format, size, sha256, section/import counts
moon run cmd/main -- scan examples --out manifest.json

# 2. which imported API is called from where (PE)
moon run cmd/main -- xref examples/notepad.exe --out xref.json

# 3. search the extracted text of every file at once
moon run cmd/main -- search examples HeapAlloc
```

Browser: `bash web/build.sh && cd web && python -m http.server 8080` → drop a binary, search its text.

## Evidence

| Check | Result |
|---|---|
| `scan` on notepad.exe | 7 sections, 315 imports — matches objdump |
| `xref` on notepad.exe | 340 IAT slots (import + delay-import), 1606 call sites, 295 distinct APIs |
| attribution false positives | **0** — every attributed address exists in the import table |
| wasm workbench | 15/15 node assertions on the real `web.wasm`, numbers identical to the CLI |
| tests | 26 unit tests, `--deny-warn` clean |

Two findings from building this, both documented in the code:

- moonpe's `Pe::iat()` strides slots by 16 bytes in a 64-bit image; the real IAT steps by 8. From the second descriptor on, every slot address is wrong. moonforge reads the IAT from the PE specification instead.
- x86-64 imports are called as `call qword ptr [rip+0x29175]`, not `call rel32`. Handling only the latter returns zero results on real binaries.

## Sources and licenses

moonforge composes; it does not reimplement. Each dependency is used through its public API, unmodified:

| Package | Version | Role | License |
|---|---|---|---|
| [NaIWaniubi/moonbin](https://github.com/NaIWaniubi/moonbin) | 0.6.0 | container parsing, x86-64 disassembly, CFG, call graph | Apache-2.0 |
| [Rz-coder8848/moonpe](https://github.com/Rz-coder8848/moonpe) | 0.8.1 | PE supplementary views (resources, .NET, certificates) | Apache-2.0 |
| [NaIWaniubi/moonseek](https://github.com/NaIWaniubi/moonseek) | 0.17.5 | full-text index and ranking | Apache-2.0 |
| [Han-Wentao/moonplist](https://github.com/Han-Wentao/moonplist) | 0.1.1 | Apple property lists (bundle profiling) | Apache-2.0 |
| [clbbbb/moonbit-wasm-inspect](https://github.com/clbbbb/moonbit-wasm-inspect) | 0.1.0 | WebAssembly module inspection | Apache-2.0 |

moonforge itself is Apache-2.0. It is unrelated to `Lyhdsba/moonforge` (a build task runner); the registry namespaces packages by author.

## What it does not do

`xref` attributes only statically-encoded calls that land exactly on an import slot. Indirect calls are counted, never guessed. An address that belongs to no data directory is refused rather than named. Linear-sweep disassembly can mis-split when data is interleaved with code — documented, not hidden.

Bundle profiling (moonplist) and wasm-module inspection are the next slice; they are not claimed here.
