// moonforge — 把 MoonBit 生态的单件工具锻造成一条逆向工作流。
// 聚合来源：NaIWaniubi/moonbin（容器解析+x86-64反汇编+CFG+调用图）、
// Rz-coder8848/moonpe（PE IAT/资源/.NET 元数据）、NaIWaniubi/moonseek（全语料检索）、
// Han-Wentao/moonplist（Apple plist）、clbbbb/moonbit-wasm-inspect（WASM 体检）。
// 注：registry 按作者命名空间解析，与 Lyhdsba/moonforge（构建任务跑）无冲突。

name = "NaIWaniubi/moonforge"

version = "0.2.0"

readme = "README.md"

repository = "https://github.com/NaIWaniubi/moonforge"

license = "Apache-2.0"

keywords = [
  "reverse-engineering",
  "binary-analysis",
  "evidence",
  "diff",
  "sarif",
  "policy-gate",
  "ci",
  "wasm",
]

preferred_target = "native"

description = "Cross-format binary evidence, deterministic release diff, and CI policy gates in pure MoonBit: PE/ELF/Mach-O/plist/WASM facts with provenance, native CLI, and offline WASM workbench."

import {
  "NaIWaniubi/moonbin@0.6.0",
  "Rz-coder8848/moonpe@0.8.1",
  "NaIWaniubi/moonseek@0.17.5",
  "Han-Wentao/moonplist@0.1.1",
  "clbbbb/moonbit-wasm-inspect@0.1.0",
  "moonbitlang/x@0.5.6",
}
