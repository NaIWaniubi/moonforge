# MoonForge 验收证据

## 本地命令

```bash
moon check --deny-warn
moon test -j 1
moon build --target native cmd/main
moon build --target native cmd/bundle
moon build --target native cmd/wasmcheck
moon build --target native cmd/diff
moon build --target native cmd/gate
bash web/build.sh
node test/web_node_check.mjs
node test/cli_contract.mjs
node scripts/mutation_check.mjs 10000
node scripts/cross_check.mjs
node bench/run_bench.mjs 1000
bash scripts/clean_clone_check.sh
```

## 关键数字

- MoonBit 单测：44/44
- WASM 断言：21/21
- 变异 harness：10,000 inputs，0 failures
- notepad.exe xref v2：3,285 decoded calls / 1,606 attributed sites / 295 APIs / 1,679 unresolved direct
- PE sections：MoonForge 7，objdump 7
- CLI contract：diff JSON/SARIF、gate 0/1/2 全部通过
- 基准：100 文件 p50 1.41 ms，p95 14.15 ms（本机 Windows，仅供参考）
- 申报书：`submission/PROPOSAL.pdf` 已生成并核验为 **1 页 A4**，预览见 `submission/PROPOSAL-preview.png`

## 待补链接

- GitHub Actions：待推送后填写
- GitHub Pages：待部署后填写
- mooncakes：待发布后填写
- 飞书提交记录截图：待提交后填写
