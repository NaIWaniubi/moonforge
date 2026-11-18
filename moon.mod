// moonforge — 把 MoonBit 生态的单件工具锻造成一条逆向工作流。
// 聚合来源：NaIWaniubi/moonbin（容器解析+x86-64反汇编+CFG+调用图）、
// Rz-coder8848/moonpe（PE IAT/资源/.NET 元数据）、NaIWaniubi/moonseek（全语料检索）、
// Han-Wentao/moonplist（Apple plist）、clbbbb/moonbit-wasm-inspect（WASM 体检）。
// 注：registry 按作者命名空间解析，与 Lyhdsba/moonforge（构建任务跑）无冲突。

name = "NaIWaniubi/moonforge"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/NaIWaniubi/moonforge"

license = "Apache-2.0"

keywords = [
  "reverse-engineering",
  "aggregator",
  "orchestration",
  "binary-analysis",
  "search",
  "corpus",
  "cli",
  "wasm",
]

preferred_target = "native"

description = "A pure-MoonBit workbench that composes five ecosystem tools (moonbin, moonpe, moonseek, moonplist, moonbit-wasm-inspect) into one reverse-engineering workflow: scan a corpus of binaries, cross-reference imported APIs against call sites, profile app bundles, and inspect WebAssembly modules — from one CLI or one browser tab."

import {
  "NaIWaniubi/moonbin@0.6.0",
  "Rz-coder8848/moonpe@0.8.1",
  "NaIWaniubi/moonseek@0.17.5",
  "Han-Wentao/moonplist@0.1.1",
  "clbbbb/moonbit-wasm-inspect@0.1.0",
}