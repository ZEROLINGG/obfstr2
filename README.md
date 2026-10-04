# obfstr2

> **Polymorphic compile-time string/bytes/file obfuscation**

[![Crates.io](https://img.shields.io/crates/v/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Downloads](https://img.shields.io/crates/d/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Documentation](https://docs.rs/obfstr2/badge.svg)](https://docs.rs/obfstr2)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#开源协议-license)

[![CI](https://github.com/ZEROLINGG/obfstr2/actions/workflows/ci.yml/badge.svg)](https://github.com/ZEROLINGG/obfstr2/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](#最小-rust-版本-msrv)

**语言：** [English](README_en.md) | 简体中文

Polymorphic compile-time string/bytes/file obfuscation（no_std 兼容）。

与 [CasualX/obfstr](https://github.com/CasualX/obfstr) 同类但路线不同：CasualX 以极小的展开体积实现开箱即用的字符串隐藏；obfstr2 则以约 6 倍的展开体积换取多形态防御——随机分块、原语随机叠加、多存储形态、垃圾代码干扰，使同一输入每次编译产出不同密文，批量还原脚本无法复用固定模式。另一关键差异是数据生命周期：obfstr2 的容器类型（`lib-unknown` 提供）在 `Drop` 时自动 volatile 清零，解密出的明文用完即擦，不会残留在栈 / 堆上。这就是为什么要有 obfstr2：**更高的逆向成本、更多态的混淆、敏感数据生命周期结束自动擦除**。

- 同：字面量进、表达式出；`no_std` 可用；混淆在编译期完成、运行时仅依赖 `lib-unknown`。
- 异：CasualX 宏返回借用临时值的引用（`let x = obfstr!(...)` 会触发 E0716，只能内联使用），obfstr2 返回自有容器，可绑定、传递、复用；CasualX 单形态展开，obfstr2 每次编译形态皆不同。

底层随机数与密码原语来自 [`lib-unknown`](https://github.com/ZEROLINGG/lib-unknown)。


## 目录

- [设计哲学](#设计哲学-design-philosophy)
- [快速开始](#快速开始-quick-start)
- [宏一览](#宏一览)
- [适用场景 vs 不适用场景](#适用场景-vs-不适用场景)
- [特性标志](#特性标志-feature-flags)
- [平台与环境支持](#平台与环境支持)
- [最小 Rust 版本](#最小-rust-版本-msrv)
- [性能](#性能-benchmarks)
- [安全性](#安全性-security)
- [贡献](#贡献-contributing)
- [变更日志](#变更日志-changelog)
- [开源协议](#开源协议-license)

## 设计哲学 (Design Philosophy)

### 核心原则

1. **极度多态化** —— 同一份输入每次编译产出不同的密文形态：随机分块（`2i..8i` 递增随机切分）、加解密原语随机叠加（`1~3 × magnification` 个，组合安全度达标即停）、多种随机存储形态（字节串 / `u8` 数组 / `u64` 数组 / `u128` 数组 / MAC / UUID / IPv6 隐写等）、垃圾代码与 `ghost_state` 干扰。批量还原脚本无法依赖固定模式。
2. **混淆流程抽象化** —— 全部算法收敛为两张注册表：`Crypto { enc / dec / support / security / latency }`（多态加解密）与 `Storage { ast / support / security / latency }`（多态密文存储），`build_obfuscated_bytes` 只负责分块→加密→存储→发射的编排。新增算法只需追加表项，无需改动流程。
3. **编译期求值、最小运行时依赖** —— 过程宏展开为封闭 Token 流，混淆在编译期完成，运行时仅依赖 `lib-unknown` 的 `types` 与 `crypto`；`no_std` 可用；展开期已验证的不变量用 `unwrap_unchecked`，不留运行时校验开销。

### 权衡取舍 (Trade-offs)

| 我们选择了 | 而不是 | 原因 |
| :--- | :--- | :--- |
| 编译时间与体积换强度 | 运行时解密开销最小化 | 高档位 1KB 输入可膨胀至约 76KB 代码（见性能），运行时仅为线性解密 |
| 每次编译结果不同 | 可复现构建 | 多态是核心防御手段，同一产物哈希必然变化 |
| 效果型混淆 | 密码学安全承诺 | 目标是抬高批量脚本还原成本，而非抗定向人工逆向 |

### 非目标 (Non-Goals)

- 不做控制流混淆与反调试。
- 不保证可复现构建、不替代加密存储敏感数据。

## 快速开始 (Quick Start)

```toml
[dependencies]
obfstr2 = "0.1"
```

```rust
use obfstr2::{b2, f2, s2, s_fmt};

fn main() {
    // 字符串：求值即得原文，返回自有容器，可绑定、传递、复用
    let hello = s2!("hello");
    print!("{hello}");
    // 字节串 / 字节数组：解引用即得原文 `[u8]`
    let b = b2!(b"abc");
    let c = b2!([0x61, 98, 99]);
    assert_eq!(&*b, &*c);
    // 文件：路径相对被编译 crate 的 CARGO_MANIFEST_DIR，编译期读入
    let d = f2!("assets/secret.bin");
    // 格式化字符串：字面量片段逐个混淆后走 `format!`，占位符照常使用，返回 `String`
    let name = "world";
    let greeting = s_fmt!("hello, {}!", name);
    print!("{greeting}");
}
```

## 宏一览

| 宏 | 输入 | 强度档 |
|---|---|---|
| `s1!` / `s2!` / `s3!` | `"..."` 字符串字面量 | 低延迟 / 均衡 / 高强度 |
| `b1!` / `b2!` / `b3!` | `b"..."` 或 `[0x41, 66, ...]`（元素 0..=255） | 低延迟 / 均衡 / 高强度 |
| `f1!` / `f2!` / `f3!` | `"path/to/file"` 文件路径字面量 | 低延迟 / 均衡 / 高强度 |
| `s_fmt!` | `"...{}..."` 格式串 + 参数（2 档） | 字面量片段混淆后走 `format!`，返回 `String`（需 `std` / `alloc`） |

说明：

- 字符串宏展开为 `StackStr<N>` / `HeapStr<N>`，字节与文件宏展开为 `StackBytes<N>` / `HeapBytes<N>`；返回的具体类型可能随编译变化，请使用类型推断，不要写死类型标注。
- 每次编译的混淆结果都不同（编译期随机），同一宏名的输出字节流不可复现。

## 适用场景 vs 不适用场景

**适合：**

- `no_std` 固件 / 裸机程序中隐藏字符串与常量字节。
- 需要规避静态字符串批量扫描的场景。

**不适合：**

- 需要合规审计、明文可读的场景。
- 超大文件混淆（代码体积膨胀约 30~70 倍，见性能）。
- 需要制品哈希稳定（可复现构建）的发布流程。

## 平台与环境支持

- `no_std` 可用；`Heap*` 类型需启用 `alloc` feature。
- `fN!` 读取的文件需在编译时存在（路径相对被编译 crate 的 manifest 目录）。

## 特性标志 (Feature Flags)

| Feature | 默认启用 | 说明 |
| :--- | :--- | :--- |
| `default` | ✅ | `lib-unknown/alloc` + `obfstr2-macros/alloc`，开启 `Heap*` 堆内存类型 |
| `alloc`（各 crate 独立） | ❌ | 关闭时仅 `Stack*` 可用（纯栈、无堆，`no_std` 裸机可用） |

## 最小 Rust 版本 (MSRV)

MSRV 未在 `Cargo.toml` 声明，在`rustc 1.98.1`测试稳定。

## 性能 (Benchmarks)

以下为 dyntest 端到端实测示例（1024 字节输入，dev profile，展开后代码体积与运行时解密耗时，仅供量级参考）：

| 档位 | 展开体积 | 运行耗时 |
| :--- | :--- | :--- |
| `b1!` | 约 39KB | 约 0.7ms |
| `b2!` | 约 50KB | 约 2.6ms |
| `b3!` | 约 76KB | 约 4.2ms |
| `s1!` / `s2!` / `s3!` | 约 34KB / 39KB / 67KB | 随档位递增 |

### 与 CasualX/obfstr 对比

展开体积为本次实测（`cargo-expand 1.0.126`，64 字节同语义程序，单位为展开后源码字符数）；运行耗时引用仓库既有 dyntest 日志（1024 字节输入，dev profile）。

| 场景 | obfstr2（`s2!` / `b2!`） | CasualX/obfstr | 倍率 |
| :--- | :--- | :--- | :--- |
| 字符串展开体积 | 20520 | 3304 | 约 6.2× |
| 字节展开体积 | 16999 | 2803 | 约 6.1× |
| 字符串运行耗时 | `s1` 0.79ms / `s2` 2.2ms / `s3` 3.4ms | 约 0.6ms | 约 1.3~5× |
| 字节运行耗时 | `b1` 0.73ms / `b2` 2.7ms / `b3` 4.2ms | 约 0.67ms | 约 1.1~6× |

| 维度 | obfstr2 | CasualX/obfstr |
| :--- | :--- | :--- |
| 展开形态 | 每次编译皆不同（随机分块 / 原语叠加 / 多存储形态 / 垃圾代码） | 固定单形态 |
| 返回值 | 自有容器，可 `let` 绑定传递 | 借用临时值的引用，`let` 绑定触发 E0716，只能内联使用 |
| 明文生命周期 | `Drop` 时 volatile 自动擦除 | 无擦除 |
| 体积 / 速度 | 大约 6 倍体积、数倍耗时 | 极小极快 |

解读：多花的体积与时间买的是批量还原成本——固定形态可被脚本一次性通杀，多形态则每编译一次就换一套特征。

## 安全性 (Security)

如发现安全漏洞，请直接提交 Issue 说明（本仓库暂无私有上报通道）。

## 贡献 (Contributing)

欢迎提交 Issue 和 Pull Request！

- 本地验证：`cd obfstr2-macros && cargo test --lib`（dyntest 会现场编译临时工程，完整套件约需数分钟）。
- 提交 PR 前请先阅读[设计哲学](#设计哲学-design-philosophy)：新增混淆原语请以 `Crypto` / `Storage` 表项形式接入（分别位于 `obfstr2-macros/src/crypto.rs` 与 `storage.rs`），编排层（`core.rs::build_obfuscated_bytes`）保持不动。

## 变更日志 (Changelog)

版本变更详情请见 [CHANGELOG.md](CHANGELOG.md)。

## 开源协议 (License)

[MIT License](./LICENSE)
