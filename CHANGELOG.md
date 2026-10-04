# Changelog

本文件记录本项目所有值得关注的变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

> **版本号说明（0.x 阶段）**：在 1.0.0 发布之前，次版本号（`0.MINOR.0`）的变更
> 也可能包含破坏性改动，请留意标注为 **[BREAKING]** 的条目。

---

## [未发布] (Unreleased)

### 新增 (Added)
-

### 变更 (Changed)
-

### 修复 (Fixed)
-

---

## [0.1.2] - 2026-10-04

### 新增 (Added)
-

### 变更 (Changed)

- 内部重构（无面向用户的行为变化）：`obfstr2-macros` 的 `bytes.rs`（1348 行）按职责拆分为 `crypto.rs`（加解密原语注册表）、`storage.rs`（密文存储策略注册表）、`core.rs`（分块→加密→存储→发射编排）、`bytes.rs`（仅留 `b1`/`b2`/`b3` 档位入口与测试）；顺带消除两处重复：MAC/UUID/IPv6 运行时 hex 解析循环合并为公共片段，主流程与垃圾块共用原语过滤入口
- 文档修正（中英同步）：存储形态不再写死数量（新增 MAC / UUID / IPv6 隐写策略后共 7 种，改为开放式表述）；修正“零运行时依赖”表述为运行时仅依赖 `lib-unknown` 的 `types` 与 `crypto`；贡献指引补上拆分后的文件位置

### 修复 (Fixed)
-

---

## [0.1.1] - 2026-10-03

### 新增 (Added)

- 格式化字符串宏 `s_fmt!`（2 档）：首参字面量的文本片段逐个混淆后注入 `format!` 调用，占位符与后续参数原样保留，返回 `String`；`README` 中英宏一览表同步

### 变更 (Changed)
-

### 修复 (Fixed)
-

---

## [0.1.0] - 2026-10-03

### 新增 (Added)

- 首个版本：`obfstr2` 根 crate（转发 `crypto` / `types` / 全部混淆宏）与 `obfstr2-macros` 过程宏 crate
- 字符串宏 `s1!` / `s2!` / `s3!`（低延迟 / 均衡 / 高强度三档，输入 `"..."`）
- 字节宏 `b1!` / `b2!` / `b3!`（输入 `b"..."` 或 `[0x41, 66, ...]` 数组，元素须为 0..=255 整数字面量）
- 文件宏 `f1!` / `f2!` / `f3!`（输入路径字面量，相对被编译 crate 的 `CARGO_MANIFEST_DIR` 编译期读入）
- 非法输入（越界数组元素、缺失文件）经 `compile_error!` 定位到调用点
- `README.md`（简体中文）与 `obfstr2-macros/README.md` 指向说明
- 端到端 dyntest 用例：宏展开→编译→运行→断言还原（含 `no_std` 裸机链路）

### 变更 (Changed)

- 包名由 `obfstr` 改为 `obfstr2`（与 crates.io 第三方 `obfstr` 区分）；生成代码路径同步为 `::obfstr2::`
- 底层依赖由本地 `path` 切换为 crates.io `lib-unknown = "0.1"`
