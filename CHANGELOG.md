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

## [0.1.4] - 2026-10-04

### 新增 (Added)
-

### 变更 (Changed)
- 测试分层迁移：宏正确性（`s1~3/b1~3/f1~3`）与 `s_fmt` 对拍迁入根 `tests/smoke.rs` / `tests/s_fmt.rs`（进程内断言，毫秒级）；非法输入与裸机链路迁入根 `tests/compile_fail.rs` / `tests/nostd.rs`（各用例隔离的 dyntest 工程，无共享 `RUNNER`）；`obfstr2-macros` 内仅留纯单元测试（格式串切分、多态展开）；移除 `macros` 对 `dyntest` 的 dev 依赖；README 中英贡献指引同步
- 双 `Cargo.toml` 补 `rust-version = "1.98"`，与 README 徽章/MSRV 章节对齐
- `assets/secret.bin` 改名 `assets/fixture.bin`（内容不变），避免文件名命中密钥扫描规则；`f2!` 示例（中英 README）与宏文档同步
- `README_en.md` 的 `i18n-sync-anchor` 刷新至当前 `README.md`
- `.gitignore` 追加环境变量/密钥/临时文件标准条目（`Cargo.lock` 忽略行保持不动，见报告说明）

### 修复 (Fixed)
- `s_fmt` 端到端对多行 pretty-debug 输出（`{v:#?}`）按行解析错位导致误报，改为被测程序内 `assert_eq!`，天然免疫换行
- `clear_dny_project(None)` 与并行测试互相等待存活锁导致 `cargo test` 挂起（`clear` 用例运行超 60 秒），删除全局清理与共享工程，改各用例独立目录
- 裸机模板缺全局分配器，`b2` 随机展开为 `HeapBytes` 时链接失败，模板补极简 bump 分配器；`b1` 增 `default-features = false` 真无分配覆盖
- 移除 6 处文件顶 `#![allow(unused)]`（根 `src/lib.rs` + macros 的 `bytes/core/crypto/storage/str`），`unused` 检查恢复生效；顺带清理其掩盖的 4 处问题：`str.rs` 删除 3 个未用导入（`Literal2`/`format_ident`/`LazyLock`），`bytes.rs` 测试 helper 删除未用 `input` 变量；`Storage::security` 当前仅作注册表元数据（选择逻辑暂只按 `support`/`latency` 过滤），改为单字段 `#[allow(dead_code)]` 并注明预留用途

---

## [0.1.3] - 2026-10-04

### 新增 (Added)

- crates.io 关键词与分类：`obfstr2` 新增 `keywords`（obfuscation / string / no-std / compile-time / polymorphic）与 `categories`（no-std / embedded）；`obfstr2-macros` 新增 `keywords`（obfuscation / proc-macro / string / no-std / compile-time）与 `categories`（no-std / development-tools）

### 变更 (Changed)

- 快速开始示例扩写（中英同步）：`s2!` 改为绑定演示可传递复用，`b2!` 加字节串/数组等价断言，新增 `s_fmt!` 示例；示例经临时工程实测可编译运行
- `src/lib.rs` 改为 `#![doc = include_str!("../README.md")]`，README 快速开始成为 doctest 在 CI 中真实执行；新增 `assets/secret.bin` 作为 `f2!` 示例的编译期 fixture；`[MIT License](LICENSE)` 改为 `./LICENSE` 以通过 rustdoc 链接检查（中英同步）

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
