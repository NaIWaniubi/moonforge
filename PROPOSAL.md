# moonforge 项目申报书

## 1 项目名称

moonforge — 把 MoonBit 生态的单件工具锻造成一条逆向工作流

## 2 项目简介

逆向一个样本，今天要在四五个工具之间来回搬数据：解析器读导入表，反汇编器读 .text，计数器统计调用，最后靠人脑把两边对上。MoonBit 已经有了这些零件（moonbin、moonpe、moonseek、moonplist、moonbit-wasm-inspect），但没有一个地方把它们接起来，更没有那一步"导入的 API 到底被谁调用"的交叉。

moonforge 就是这条流水线。给它一个目录，它输出每份文件的结构清单、哈希与节/导入计数；给它一个 PE，它把导入表的每个槽和反汇编里每一条静态调用对齐，告诉你 VirtualAlloc 被调用几次、每次在哪个地址；给它一句查询，它在你语料里所有文件的字符串中排序命中并给出上下文。同一份代码编译成命令行和 wasm，浏览器里拖进文件就能用，没有后端。

## 3 项目方向与通用性

方向是开发者工具里的组合层。我不主张再填一个解析器——那个格子已经被 moonpe、machscope、dwarfscope 占了；我填的是它们之间的缝：

- 组合：五个包的公开 API 在一个流程里串起来，一次输入走完"结构 → 交叉 → 检索"。
- 编排：命令行与浏览器共享同一份 MoonBit 代码，`src/peinfo` 是唯一的 IAT 实现，CLI 和 wasm 都调它，不存在两份会漂移的逻辑。
- 交叉层是原创：IAT 槽 → `call rel32` / `call qword ptr [rip+disp]` 的归因，这五个包里没有任何一个提供。

通用性：核心不碰文件系统、不联网，输入是字节、输出是 JSON；同一套库既能做命令行工具，也能进网页，也能被别的 MoonBit 项目 import 复用。

## 4 预期使用场景

1. **样本初筛**：`scan` 一个目录，一次看清每份文件的格式、大小、哈希和导入数量，先把可疑的挑出来。
2. **API 使用面盘点**：`xref` 告诉我某个导入在样本里被调用多少次、调用点在哪。notepad.exe 上 GetProcessHeap 146 次、SendMessageW 111 次——这个数字比读代码猜更可信。
3. **跨文件检索**：`search` 把目录里所有文件的字符串建索引，一句查询命中并带上下文，省掉逐文件 grep 二进制。
4. **浏览器里零安装**：拖进一个 PE，结构、交叉引用计数、Top API 和文本检索一次出全，不用装工具链。

## 5 拟实现的核心功能（已完成部分）

- `scan`：格式判定（MZ / ELF magic / 四种 Mach-O magic / fat）、sha256、节/符号/导入/导出计数；未知格式不送解析器，只记录。
- `xref`：读 PE 导入与延迟导入描述符，建 IAT 槽表，解析 `.text` 里的 `call rel32` 与 rip 相对导入调用，按槽精确归因；间接调用单独计数，不推测。
- `search`：提取可打印 ASCII 串（≥4 字节，不做有损 UTF-8 解码），喂 moonseek 建索引，输出带上下文的命中。
- wasm 工作台：同一份代码编译到 wasm，node 与浏览器两条腿都验证。

正确性证据：notepad.exe 上 340 个 IAT 槽（导入 + 延迟导入）、1606 个已解析调用点、295 个不同 API，与 objdump 逐地址对照 **0 假阳性**（每个归因地址都真实存在于导入表）。26 个单元测试全绿，`--deny-warn` 无告警。

初审问过"边界怎么维持"，这里把归因规则写死，每条都对应代码里的一个分支：

1. **只认两种静态编码的调用**：`call rel32`（E8）与 `call qword ptr [rip+disp]`。目标必须精确落在 IAT 槽地址上才算归因成功；目标不是槽的一律不计入站点数，也不另造边。
2. **槽表从描述符自己读**：标准导入描述符 + 延迟导入描述符（数据目录 13）；槽数取 INT 与 IAT 长度的较大值，因为 bound image 的 INT 会截断（notepad 最后一个描述符 INT 长 1、IAT 长 7）——截断处标 `#unresolved`，不猜函数名。
3. **间接调用单独计数**（`call rax`、`call [mem]`）：计入 indirect_calls，永远不参与归因，也不推测目标。
4. **不属于任何数据目录的地址拒绝命名**：notepad 的 0x14002a450 是 .rdata 里的指针，但不在任何导入表里，所以 objdump 统计的导入调用是 2058 条而本项目归了 1606 条——差的这部分明写是"我们不知道"，不是"我们猜"。
5. **线性扫描的固有局限写明**：原始数据与代码混排时边界可能错位，这是线性扫描的性质，不是递归下降，不回避。

命令行与浏览器共享同一份 MoonBit 代码：`src/peinfo` 是唯一的 IAT 实现，CLI 与 wasm 都调它，不存在两份会漂移的逻辑。wasm 侧在 node 里对真实 notepad.exe 跑了 15 项断言，数字与 CLI 完全一致；页面拖文件的交互还没在真 Chrome 里跑过，这句是结构事实，不是现场证据。

做这个项目时挖出两个真问题，都写进了代码注释：moonpe 的 `Pe::iat()` 在 64 位镜像里按 16 字节步进（真实 IAT 是 8 字节），第二个描述符起全部错位——所以本项目的 IAT 按 PE 规范自己读；x86-64 的导入调用是 `call qword ptr [rip+0x29175]` 而不是 `call rel32`，只认后者在真实二进制上得到 0 个结果。

## 6 原创性

原创。组合层、编排层与 IAT→调用点交叉都是自己写的，没有复制任何现有实现。被组合的五个包以公开 API 依赖，未改动其代码。

## 7 参考与依赖说明

| 依赖 | 版本 | 作用 | 许可证 |
|---|---|---|---|
| NaIWaniubi/moonbin | 0.6.0 | 容器解析、x86-64 反汇编、CFG、调用图 | Apache-2.0 |
| Rz-coder8848/moonpe | 0.8.1 | PE 补充视图（资源、.NET、证书） | Apache-2.0 |
| NaIWaniubi/moonseek | 0.17.5 | 全文索引与排序 | Apache-2.0 |
| Han-Wentao/moonplist | 0.1.1 | Apple plist（bundle 画像） | Apache-2.0 |
| clbbbb/moonbit-wasm-inspect | 0.1.0 | WebAssembly 模块体检 | Apache-2.0 |

本项目 Apache-2.0。与 `Lyhdsba/moonforge`（构建任务跑）无功能交集，同名因注册表按作者命名空间。

## 8 GitHub 仓库链接

https://github.com/NaIWaniubi/moonforge

仓库公开，提交连续，每个提交带"为什么"。CI 覆盖 check / test / native build / wasm build 四项。