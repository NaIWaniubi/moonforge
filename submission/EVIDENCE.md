# MoonForge 验收证据

## 本地命令

```bash
moon fmt --check
moon check --deny-warn
moon test -j 1
moon build --target native cmd/main
moon build --target native cmd/bundle
moon build --target native cmd/wasmcheck
moon build --target native cmd/diff
moon build --target native cmd/gate
moon build --target wasm --release src/web
bash web/build.sh
node test/web_node_check.mjs
node test/cli_contract.mjs
node scripts/mutation_check.mjs 10000
node scripts/cross_check.mjs
node bench/run_bench.mjs 1000
bash scripts/clean_clone_check.sh
```

## 关键数字

- MoonBit 单测：54/54
- WASM 断言：24/24
- 变异 harness：10,000 inputs，0 failures
- notepad.exe xref v2：3,285 decoded calls / 1,606 attributed sites / 295 APIs / 1,679 unresolved direct
- PE sections：MoonForge 7，objdump 7
- CLI contract：diff JSON/SARIF、gate 0/1/2、错误 stdout JSON 全部通过
- 基准：1000 文件 p50 1.47 ms，p95 14.02 ms，默认门限 150 ms（本机 Windows）
- SARIF：输出通过 SARIF 2.1.0 官方 schema 校验
- 真实浏览器：ZCode 内置 Chrome 完成 Demo 加载、拖放、5 artifact 自动分析、policy BLOCK、非法 policy 失败关闭、JSON 导出；截图见 `submission/browser-gate.png`
- 申报书：最终提交 `PROPOSAL.md`（Markdown）；`submission/PROPOSAL.pdf` 仅作预览，不上传。内容仍为 AI 底稿，提交前必须由用户本人重写

## 线上链接

- GitHub Actions（Ubuntu + Windows 全绿）：https://github.com/NaIWaniubi/moonforge/actions/runs/45896068370
- GitHub Pages（HTTP 200，真实 Chrome 复验）：https://naiwaniubi.github.io/moonforge/
- Pages 验收截图：`submission/pages-gate.png`
- mooncakes：`NaIWaniubi/moonforge@0.2.0` 已发布；`moon view` 元数据见 `submission/mooncakes-view.json`
- GitHub tag：`v0.2.0`
- 飞书提交记录截图：待提交后填写
