# moonforge · 接口契约（冻结版 v0.1）

实现前先读。每个切片只允许动自己拥有的目录与文件；跨包调用只走本文件列出的签名。
所有包文件头写清楚该切片负责什么，改动要带上 `// why:` 注释。

## 依赖事实（已核实）

| 依赖 | 版本 | 提供什么 |
|---|---|---|
| NaIWaniubi/moonbin@0.6.0 | 已发布 2026-11-18 | `@moonbin.pe.parse/@moonbin.elf.parse/@moonbin.macho.parse(data)->Result[_,_]`；`Pe/Elf/MachO` 公开字段 `sections/symbols/imports/exports`（`Import{library,name}`、`Symbol{name,value,size,kind,bind,shndx}`、`Region{name,offset,size,vaddr,flags}`）；`@disasm.disassemble(bytes,addr,count)->Array[Insn]`（`Insn.addr/len/mnemonic/op_str/bytes`）；`@analysis.cfg(code,base)`、`@analysis.callgraph(code,base)->Array[(Int64,Int64)]` |
| Rz-coder8848/moonpe@0.8.1 | 已发布 | PE 的 IAT（thunk 地址）、resources、.NET metadata、LoadConfig —— 以拉取到的源码实际导出为准，先读再调，不得猜字段名 |
| NaIWaniubi/moonseek@0.17.5 | 已发布 | `@mooneseek.Index::new(schema)`、`add(Document)`、`search(query)->Array[Hit]`、`Hit{id,score,snippet,...}`（以源码为准） |

依赖解析失败的唯一正确处理：读源码，不准猜 API。

## 切片所有权

| 切片 | 拥有目录/文件 |
|---|---|
| S1 core+scan | `src/core/`（types.mbt、manifest.mbt）、`cmd/main/`（CLI 入口，scan 子命令）、`examples/`（fixtures：notepad.exe 等真实小样例，提交进仓库） |
| S2 xref | `src/xref/`（xref.mbt） |
| S3 corpus | `src/corpus/`（corpus.mbt） |
| S4 web | `src/web/`（main.mbt）、`web/`（静态页） |
| S5 delivery | 只动根级文档与 CI：README.md、PROPOSAL.md、LICENSE 引证、`.github/workflows/ci.yml`、`test/` 顶层脚本 |

S1 的 CLI 是唯一入口；其它切片不许自己起 CLI 分支。

## S1 · core + scan

```mbt
// src/core/types.mbt
pub enum Format { Pe, Elf, MachO, Unknown }
pub struct Summary {
  sections : Int32, symbols : Int32, imports : Int32, exports : Int32
}
pub struct FileRecord {
  path : String, format : Format, size : Int64,
  sha256 : String?,   // 计算它的函数放在 core，读文件的 #cfg 分派留在 cmd/main
  summary : Summary,
}
pub struct Manifest { files : Array[FileRecord] }
```

```mbt
// src/core/manifest.mbt
pub fn Manifest::from_bytes(...)        // 见下：从字节判定格式并汇总
pub fn Manifest::to_json(self) -> String // 自己实现 JSON 序列化，键名固定：
                                          // {"files":[{"path","format","size","sha256","summary":{...}}]}
pub fn Manifest::from_json(s : String) -> Result[Manifest, String]
```

格式判定顺序：MZ→pe；ELF magic `\x7fELF`→elf；`\xfe\xed\xfa\xce|\xcf|\xff|\x00` 或 `MH_MAGIC` 魔数→macho；否则 Unknown（对 Unknown 不 parse，直接记 summary=空）。二进制读取只发生在 `cmd/main`（native-only，`#cfg` 守卫），core 保持零文件系统依赖，能编到 wasm。

**验收**：`examples/` 下放 notepad.exe/dbg.exe/kernel32.dll 与一个非可执行文本；`moonforge scan examples/ --out manifest.json` 后用 objdump/readelf 抽查 sections/symbols/imports 数量一致（在自己的单测里断言常量）。

## S2 · xref（IAT → 调用点）

```mbt
// src/xref/xref.mbt
pub struct ApiCallSite { api : String, caller_addr : Int64, target_addr : Int64 }
pub struct XrefTable { by_api : Array[(String, Int32)] /*api -> count*/,
                        sites : Array[ApiCallSite] }
pub fn build_xref(pe_data : Bytes, text : Bytes, text_base : Int64) -> XrefTable
```

做法：把 moonbin 的 PE imports 与 moonpe 的 IAT thunk 地址对齐（取并集），对 `.text` 跑 `@disasm.disassemble` 取 `call rel32` 边（E8），目标命中某 thunk 地址即记一条 `(api, call_addr, thunk_addr)`；thunk 未解析到名字的记 `#ordinal`-类无名标签，诚实标注。不猜间接调用的目标。`#cfg` 分派保证 wasm 可编译（不含 fs 调用）。

**验收**：notepad.exe 上 VirtualAlloc/VirtualFree 等已知导入必须出现于 by_api 且 count>0，与 objdump -d 的 call 计数抽查一致；无 thunk 信息的 ELF 给出空表而不是崩溃。

## S3 · corpus（跨语料检索）

```mbt
// src/corpus/corpus.mbt
pub fn index_files(idx : @mooneseek.Index, records : Array[FileRecord],
                   strings_of : fn(Array[Bytes]) -> Array[String])
                   -> Unit
pub fn search_docs(query : String) -> Array[String]  // 返回 doc id（=相对路径）
pub fn doc_snippet(id : String, query : String) -> String?
```

每个文件一篇 Document，字段：`id`=路径（作 search id）、`body`=可打印字符串拼接 + 符号名 + 节名，中文分词走 moonseek 内置 analyzer。无 fs 依赖（由调用方喂数据）。snippet 回带命中词的上下文。

**验收**：两个 fixture（含 "VirtualAlloc" 字样的自定义 .mbt/ascii 文件各一）→ query `"VirtualAlloc"` 命中文档列表；query 噪声词零命中。

## S4 · web（wasm 工作台）

`src/web/main.mbt` 导出三个 wasm 函数：`js_scan(bytes)`→manifest json 字符串、`js_xref(pe,text)`→json、`js_search(q)`→json 字符串数组。`web/index.html` 单页：拖入文件→结构表+熵条；search 框直接查索引。JS 侧不解析 JSON 之外的协议。**验收**：node + headless Chrome 双 DOM 计数测试（参考 moonbin test/web_e2e.mjs 模式）。

## S5 · delivery

README（双语：EN 在上 ZH 在下，四段式：是什么/三条工作流命令/质量证据/依赖与许可清单——逐条列来源仓库+许可证+链接，这是"聚合器"的诚信声明，不是移植声明）；CI 覆盖 check/test/native/wasm 四项；PROPOSAL 按表单 8 点一页写成。