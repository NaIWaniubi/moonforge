# MoonForge 90 秒演示分镜

## 0–10 秒：问题

画面：左边是 PE、Info.plist、WASM 三个文件，右边是散落的解析结果。
旁白：“二进制发布最贵的不是解析，而是把证据对齐、判断变化、决定能不能放行。”

## 10–25 秒：一次输入，多格式证据

操作：打开 MoonForge Pages，拖入 `dbg.exe`、`Info.plist`、`minimal.wasm`。
画面：三张 artifact 卡片同时出现 read/parse 状态、格式、SHA-256、节/导入导出、WASM 节表。
旁白：“一份 MoonBit 核心，native 和浏览器共用；没有后端，没有 FFI。”

## 25–45 秒：从导入到调用点

操作：展开 PE 的 xref v2「调用点明细」。
画面：3,285 decoded calls、1,606 attributed sites、295 APIs；明细表列出 section、RVA、指令字节、IAT slot 与命中规则。
旁白：“每个结论都能回到字节。猜不到的 1,679 个直接目标明确留为 unresolved。”

## 45–65 秒：两个构建，一次审判

操作：拖入 old/new 两个 artifact，在 policy 文本框粘贴禁止新增 kernel32 导入的规则并点击「分析」。
画面：added / removed / changed 三列表，新增 kernel32 导入被 policy 命中，Gate 显示 BLOCK 与违规明细。
旁白：“跨格式归一化事实做 diff，声明式 policy 直接给出放行结论和 SARIF。”

## 65–80 秒：CI 门禁

操作：终端运行 `moon run cmd/gate -- old.json new.json policy.json`。
画面：stdout 为 JSON，退出码 1；旁边展示 GitHub Actions 全绿。
旁白：“同一套规则既能在浏览器里看，也能进 CI。stdout 永远机器可读。”

## 80–90 秒：收尾

画面：README、mooncakes、Pages、测试数字快速切换。
旁白：“MoonForge：事实有来源，变化可差分，决策可审计。”

## GIF 制作

1. 用 1280×800 窗口录屏，保持 30fps。
2. 按上面时间轴截取关键帧，转成调色板 GIF。
3. GIF 放在 `assets/moonforge-demo.gif`，README 顶部引用。
4. 现场演示只播放 GIF，避免实时网络或浏览器解码风险。
