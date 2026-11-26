# MoonForge 提交检查清单

## 代码与质量

- [x] `moon check --deny-warn` 通过
- [x] `moon test -j 1`：54/54
- [x] native CLI：main / bundle / wasmcheck / diff / gate 全部构建
- [x] wasm workbench 构建并通过 24/24 Node 断言
- [x] 10,000 个变异输入：0 panic / 0 hang
- [x] objdump PE 节数交叉核对通过
- [x] CLI stdout / SARIF / gate 退出码 0/1/2 契约通过
- [x] SARIF 2.1.0 官方 schema 校验通过
- [x] `moon fmt --check` 通过
- [x] 基准 p95 门禁通过（14.02 ms ≤ 150 ms）
- [x] clean clone 复现脚本已提供

## 交付物

- [x] GitHub 仓库公开
- [x] README 中英双语
- [x] `PROPOSAL.md` 八点一页底稿
- [ ] 用户本人重写 `PROPOSAL.md`，确保不是 AI 文案
- [ ] 生成并人工核验 `submission/PROPOSAL.pdf` 为一页 A4
- [x] GitHub Pages 部署并返回 200
- [x] 本地真实 Chrome 拖放 / diff / policy gate / 导出验收
- [x] Pages 真实 Chrome 复验
- [x] 发布 mooncakes 0.2.0 并保存 `moon view` 证据
- [x] 创建并推送 `v0.2.0` tag
- [x] CI 实时全绿（Ubuntu + Windows，run 45896068370）

## 报名记录

- [ ] 用户选择替换 5 条记录中的哪一条
- [ ] 原地更新项目名称、仓库、申报书、备注
- [ ] 核对 GitHub ID、身份证号、银行卡分行
- [ ] 勾选诚信承诺书并提交
- [ ] 保存提交记录截图
