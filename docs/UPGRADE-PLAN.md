# MoonForge RE Workbench · 大赛级升级规划

> 版本：v0.2 计划　日期：2026-11-26  
> 目标：把 moonforge 从“五工具聚合原型”升级为**跨格式、证据可追溯、可差分、可进 CI 的二进制发布门禁**，达到可提交、可复现、可答辩的顶级完成度。

## 1. 背景与问题

当前 moonforge 已完成 S1–S5 原型：目录扫描、PE IAT→调用点归因、跨语料检索、CLI 与 wasm 工作台。但距离大赛级交付仍有硬缺口：

- 只有 9 个有效 commit，未达到“不少于 10 个有效 commits”门槛。
- 冻结契约中的 S6（bundle profile / WASM check）完全未实现。
- `INTERFACES.md` 与现有公共 API 多处漂移。
- README/PROPOSAL 已提前声称尚未实现的五工具与 S6 能力。
- 解析失败被写成空 summary，证据工具的基本诚实性不足。
- xref 只扫描 `.text`、依赖反汇编器格式化字符串、缺完整调用账本。
- 无真实 Chrome 验收、无 Pages、无 PDF、无 tag、CI 可复现性不足。

moonbin 初审驳回的两条教训必须继承：

1. 不得宣称“MoonBit 生态为空”；解析、反汇编、熵、扫描、WASM 工具已存在。
2. 原创性必须精确到机制层，并写清边界、拒绝规则、可信范围与交叉核对证据。

## 2. 产品定位

**MoonForge RE Workbench**：

> 把 PE / ELF / Mach-O / Info.plist / WASM 变成统一、可审计的事实图；回答两个版本之间新增了什么能力、发生在哪些字节/调用点、依据是什么，并可作为 CI 发布门禁。

差异化只做三件事：

1. **证据信封**：每个 fact 带 artifact sha256、parser/依赖版本、字节位置、直接/推导/未知状态。
2. **跨格式发布差分**：old/new 归一化事实 diff，覆盖容器、导入导出、plist、WASM。
3. **基线相对门禁**：只阻断新增能力、新增导入、新增 WASM proposal、权限/元数据变化，输出 JSON/SARIF。

## 3. 非目标

- 不再堆通用 scan/strings/entropy/hex viewer。
- 不写通用恶意软件判定、YARA 替代品、反编译、仿真、脱壳。
- 不自研 x86 反汇编器、CFG、DWARF；继续依赖 moonbin。
- 不引入 FFI，不增加后端服务。
- 不把“浏览器工作台”当主创新，它只是交付与演示层。
- 不使用“第一个/唯一二进制分析工具”等与生态事实冲突的表述。

## 4. 兼容矩阵

| 能力 | Native CLI | WASM/JS | 浏览器 | 输出 |
|---|---|---|---|---|
| scan / xref / search | ✅ | ✅ | ✅ | 稳定 JSON |
| evidence 证据信封 | ✅ | ✅ | ✅ | sha256 + parser 版本 + location |
| binary diff | ✅ | ✅ | ✅ | JSON / SARIF |
| baseline policy gate | ✅ | — | ✅ | JSON / SARIF，退出码 0/1/2 |
| bundle profile | ✅ | ✅ | ✅ | Mach-O + plist JSON |
| WASM check | ✅ | ✅ | ✅ | section/import/export JSON |
| report export | ✅ | ✅ | ✅ | JSON / HTML |

格式边界：PE、ELF、Mach-O、plist、WASM 的已支持字段必须与 objdump/readelf/otool/wasm-tools 交叉核对；未知或损坏输入返回结构化错误，不写空 summary。

## 5. 架构原则

- 依赖结构体不得直接成为公共输出；每个依赖通过 adapter 转成 MoonForge 稳定事实模型。
- Diagnostic 是一等类型：`parsed / malformed / unsupported / empty` 明确区分。
- fact ID 由 artifact hash + kind + location 派生，集合/映射规范化排序，保证确定性。
- IO 外壳与纯核心分离：native 文件系统只在 CLI，wasm 通过显式协议喂字节。
- 资源限制：单文件大小、字符串长度、descriptor 数量、反汇编指令数、容器深度。
- CLI 机器契约：stdout 只放机器可读结果，摘要进 stderr，稳定退出码。
- 所有新增能力必须接入至少一条真实工作流，不做引用堆砌。

## 6. 阶段切片与集群分工

使用 Tower 6 个 mission，并发 3，每个 mission 独立 reviewer，主线程负责集成、契约、发布。

### M1 · S6 breadth

- 新增 `src/bundle/`、`src/wasmcheck/`、`fixtures_breadth/`。
- 实现 `bundle_profile` 与 `wasm_report`，补齐正负例与 wasm 可编译测试。
- 独立 `cmd/bundle`、`cmd/wasmcheck` 作为验收入口，不碰 `cmd/main`。
- 验收：plist 键集合/bundle id/version 正确；无 plist 诚实返回；坏 WASM magic 返回 Err。

### M2 · Evidence + xref v2

- 新增 `src/evidence/`；升级 `src/xref/` 与 `src/peinfo/`。
- 按 executable section 权限逐节解码，保留正确 base；从指令字节解析 call，不依赖 `op_str`。
- 完整账本：decoded / refused / direct / indirect / attributed / unresolved。
- 每个归因站点带指令字节、section、RVA/VA、IAT slot、API、规则。
- 验收：precision=1.0；固定支持编码 recall ≥99%；账目恒等；多 executable section 地址正确。

### M3 · Diff + policy gate

- 新增 `src/diff/`、`src/policy/`、`cmd/diff`、`cmd/gate`。
- old/new 归一化事实 diff；声明式 policy；JSON/SARIF 2.1.0；退出码 0/1/2。
- 验收：相同文件 diff 为空；种子变更 100% 召回、0 误报；SARIF schema 通过；stdout 始终可解析。

### M4 · Web 工作台 + Pages

- 改 `src/web/`、`web/`、`.github/workflows/pages.yml`。
- 多文件拖放、scan/xref/diff/bundle/wasm 面板、证据定位、报告导出。
- 真实 Chrome DOM 验收，不只 Node。
- 验收：Pages 200、无 console error、native/wasm canonical JSON 一致、离线无后端请求。

### M5 · 质量基础设施

- 改 `.github/workflows/ci.yml`；新增 `test/`、`bench/`、`scripts/`。
- 固定 MoonBit 版本、lock 校验、native/wasm artifact、mutation/property test、真实 fixture 交叉核对、性能基线。
- 验收：clean clone 全绿；10k 变异 0 panic/0 hang；外部工具支持字段 100% 一致；性能回退有门禁。

### M6 · 文档与申报包

- 改 `README.md`（真正双语）、`PROPOSAL.md`、`docs/`、`submission/`。
- 一页 A4 PDF 生成脚本、演示 GIF、依赖/许可清单、同名包消歧、提交检查清单。
- 验收：PDF 一页；链接 200；README/PROPOSAL 每项能力都有命令、测试或截图证据。
- 注意：PROPOSAL 最终必须由用户本人按“不要使用 AI 编写”的要求重写确认。

## 7. 验收断言

- `moon check --deny-warn`、`moon test`、native build、wasm build 全绿。
- CLI golden tests 覆盖 scan/xref/search/diff/bundle/wasm/gate；连续两次 JSON 字节一致；native/wasm 同输入输出一致。
- PE xref 对 objdump 的支持字段 100% 一致，precision=1.0，call 账目恒等。
- ELF/Mach-O/WASM 对 readelf/otool/wasm-tools 100% 支持字段一致。
- 10,000 个变异/损坏输入：0 panic、0 hang；错误带原因与位置。
- diff 种子变更 100% 召回、0 误报；100% finding 带 sha256 + parser 版本 + location。
- 真实 Chrome：多文件拖放、diff、导出全通过，无 console error；Pages 200。
- clean clone 一键复现；CI 实时全绿；有效 commit ≥10；tag `v0.2.0`；mooncakes `moon view` 可查。
- `PROPOSAL.pdf` 为 A4 一页且用户已本人复核。

## 8. 风险与回滚

- **契约漂移**：集成时只允许主线程修改 `INTERFACES.md`，升 v0.2 并写迁移说明；worker 不猜 API。
- **文档超前**：M6 只写已实现且可复现的能力；未实现项统一标 “not claimed”。
- **依赖 API 变化**：先读 `.mooncakes` 源码再调用；禁止凭记忆猜字段。
- **Tower 旧状态**：启动前检查 `.tower/`，保留历史但新建 run；master 必须干净。
- **浏览器协议扩展**：保留旧单文件协议兼容，新增多文件协议版本号。
- **发布失败**：先本地打包复检，再 `moon publish`；失败不 tag、不提交表单。
- **时间风险**：先完成 P0 证据/diff/gate/S6，再做视觉抛光；最终提交前不再加未验证功能。

## 9. 提交流程

全部验收通过后：

1. 推 GitHub 并确认 CI 全绿。
2. 部署 GitHub Pages 并截图。
3. 发布 mooncakes `v0.2.0`，保存 `moon view` 证据。
4. 生成提交证据包（命令、测试、截图、PDF、哈希）。
5. 请用户选择替换 5 条飞书记录中的哪一条。
6. 原地更新记录、核对字段、提交并截图留证。
