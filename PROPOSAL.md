<!-- 提交前请用户本人用自己的话重写本稿，以符合表单“不要使用 AI 编写”的要求。 -->

# MoonForge RE Workbench 项目申报书

## 1 项目名称

MoonForge RE Workbench — 跨格式二进制证据、发布差分与 CI 门禁

## 2 项目简介

我平时做逆向和发布分析，最耗时的不是解析一个文件，而是把多个工具的结果对齐：哪个导入被调用、两个构建差了什么、这个变化该不该放行。MoonBit 已经有 moonbin、moonpe、moonseek、moonplist、moonbit-wasm-inspect 这些零件，但缺少一条把它们串起来、并且能审计每个结论来源的工作流。

MoonForge 做的是这条证据链：PE / ELF / Mach-O / Info.plist / WASM 先变成统一事实，每个事实带 artifact 哈希、parser 版本和字节位置；两个版本做确定性 diff；最后用声明式 policy 决定是否放行，输出 JSON 或 SARIF。同一份 MoonBit 核心同时编译成 native CLI 和离线 wasm 浏览器工作台。

## 3 项目方向与通用性

方向是二进制发布证据与决策层，不是再写一个解析器。生态里已有容器解析、反汇编、熵扫描和 WASM 检查，我不重复它们；我填的是它们之间的缝：

- **证据信封**：所有结论带来源、状态和位置，错误不再被写成零值成功。
- **xref v2**：按可执行节逐节解码，从指令字节识别 `E8 rel32` 与带 REX 前缀的 `FF 15 rip-rel32`，精确落到 IAT 槽才归因。
- **统一差分**：把不同格式的节、导入导出、符号、plist、WASM 事实归一化后做 added / removed / changed。
- **基线门禁**：只阻断相对可信基线新增的能力，例如新增 kernel32 导入，并给出可下钻的证据。

核心输入是字节、输出是 canonical JSON，不碰文件系统、不联网，既能做 CLI，也能进浏览器，还能被其他 MoonBit 项目 import。

## 4 预期使用场景

1. **样本初筛**：扫描目录，一次得到格式、大小、SHA-256、节/符号/导入导出计数。
2. **API 使用面盘点**：对 PE 做 IAT 槽到调用点的精确归因，知道某个导入从哪些地址被调用。
3. **发布差分**：比较两个构建，直接看到新增/删除的导入、导出、节、plist 字段和 WASM 变化。
4. **CI 放行门禁**：用 policy 阻止意外新增导入或元数据变化，失败时输出 SARIF 和稳定退出码。
5. **离线浏览器分析**：拖入多个 artifact，查看证据、diff、bundle profile、WASM 节表和跨文件检索。

## 5 核心功能与正确性证据

已实现：`scan`、`xref`、`search`、`bundle`、`wasmcheck`、`diff`、`gate`，以及多 artifact 的 `moonforge-v2` 浏览器协议。

notepad.exe 上，xref v2 解码 **3,285** 条调用，精确归因 **1,606** 个站点、**295** 个 API；未命中的 **1,679** 个直接目标保留为 unresolved，不猜。每个归因目标都真实存在于 IAT 槽表中。

质量证据：**54/54** MoonBit 单测；真实 PE/plist/WASM 输入下 **24/24** wasm 断言；固定种子 **10,000** 个截断/位变异输入 **0 panic、0 hang**；PE 节数与 `objdump -h` 一致；CLI 成功与错误 stdout 均为机器可读 JSON，gate 退出码严格为 0/1/2；重复运行 canonical JSON 字节一致；基准 p95 默认门限 150 ms。

边界写明：目前只归因 `E8 rel32` 和 `FF 15 rip-rel32`；线性扫描可能被代码/数据混排误导，拒绝字节会进入账目；bundle profile 配对 Mach-O 与 Info.plist，不解包任意 ipa；policy 是小型声明式语言，不是通用编程语言。

## 6 原创性

原创部分是证据信封、section-aware 字节级 xref v2、跨格式归一化 diff 和基线 policy gate。解析、反汇编、索引、plist、WASM 检查均通过公开 API 使用现有依赖，没有复制或修改它们的实现。

## 7 参考与依赖说明

| 依赖 | 版本 | 作用 | 许可证 |
|---|---|---|---|
| NaIWaniubi/moonbin | 0.6.0 | 容器解析、x86-64 反汇编、CFG/调用图 | Apache-2.0 |
| Rz-coder8848/moonpe | 0.8.1 | PE 补充视图与独立 API 参考 | Apache-2.0 |
| NaIWaniubi/moonseek | 0.17.5 | 全文索引与排序 | Apache-2.0 |
| Han-Wentao/moonplist | 0.1.1 | Apple plist 有界解析 | Apache-2.0 |
| clbbbb/moonbit-wasm-inspect | 0.1.0 | WASM 节表/导入导出检查 | Apache-2.0 |
| moonbitlang/x | 0.5.6 | crypto、文件系统、系统工具 | Apache-2.0 |

MoonForge 本体 Apache-2.0。与 `Lyhdsba/moonforge`（增量构建任务运行器）无功能交集，mooncakes 按作者命名空间区分。

## 8 GitHub 仓库链接

https://github.com/NaIWaniubi/moonforge
