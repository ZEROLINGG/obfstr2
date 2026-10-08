# obfstr2

> **Polymorphic compile-time string/bytes/int/float/cstr/file obfuscation**

[![Crates.io](https://img.shields.io/crates/v/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Downloads](https://img.shields.io/crates/d/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Documentation](https://docs.rs/obfstr2/badge.svg)](https://docs.rs/obfstr2)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#开源协议-license)

[![CI](https://github.com/ZEROLINGG/obfstr2/actions/workflows/ci.yml/badge.svg)](https://github.com/ZEROLINGG/obfstr2/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](#最小-rust-版本-msrv)

**语言：** [English](README_en.md) | 简体中文

Polymorphic compile-time string/bytes/int/float/cstr/file obfuscation（no_std 兼容）。

与 [CasualX/obfstr](https://github.com/CasualX/obfstr) 同类但路线不同：CasualX 以极小的展开体积实现开箱即用的字符串隐藏；obfstr2 则以约数倍的展开体积换取多形态防御——随机分块、原语随机叠加、多存储形态、垃圾代码干扰，使同一输入每次编译产出不同密文，批量还原脚本无法复用固定模式。覆盖面也不止字符串：`s/b/f` 三系之外，`i1~3!` / `fl1~3!` 覆盖全部整数与浮点字面量（展开为可直接运算的裸值），`cs1~3!` 覆盖 C 字符串（`"..."` / `c"..."` / `b"..."` 三形态等价，`b"..."` 可表达非 UTF-8 载荷，展开为解引用即 `CStr` 的自有容器），`s_fmt!` 覆盖格式化字符串（字面量片段逐个混淆后走 `format!`）——七类输入走同一套分块→加密→存储→发射内核。另一关键差异是数据生命周期：obfstr2 的容器类型（`lib-unknown` 提供）在 `Drop` 时自动 volatile 清零，解密出的明文用完即擦，不会残留在栈 / 堆上（`s/b/f/cs` 容器；`i/fl` 返回裸值、`s_fmt!` 返回 `String`，无自动擦除，见宏一览说明）。这就是为什么要有 obfstr2：**更高的逆向成本、更多态的混淆、更宽的类型覆盖、敏感数据生命周期结束自动擦除**。

- 同：字面量进、表达式出；`no_std` 可用；混淆在编译期完成、运行时仅依赖 `lib-unknown`。
- 异：CasualX 宏返回借用临时值的引用（`let x = obfstr!(...)` 会触发 E0716，只能内联使用），obfstr2 返回自有容器（`i/fl` 为裸值），可绑定、传递、复用；CasualX 单形态展开，obfstr2 每次编译形态皆不同；CasualX 以字符串为主，obfstr2 另有整数 / 浮点 / C 字符串 / 文件 / 格式化五类宏。


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
4. **开箱即用的易用性** —— 调用方只写一行宏：字面量进、表达式出，无需初始化、密钥管理或运行时配置；三档编号全系统一（`1` = 低延迟、`2` = 均衡、`3` = 高强度）；返回自有容器或裸值，可 `let` 绑定、传递、复用，无需写死类型标注；非法输入在编译期直接定位到调用点报错。多态的复杂性收敛在宏内部，不外泄心智负担。

### 权衡取舍 (Trade-offs)

| 我们选择了 | 而不是 | 原因 |
| :--- | :--- | :--- |
| 编译时间与体积换强度 | 运行时解密开销最小化 | 128B 输入在 `b3` 下展开约 55k 字符、产物约 490KB（见性能），运行时为线性解密 |
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
use obfstr2::{b2, cs2, f2, fl2, i2, s2, s_fmt};

fn main() {
    // 字符串：求值即得原文，返回自有容器，可绑定、传递、复用
    let hello = s2!("hello");
    print!("{hello}");
    // C 字符串：求值即得原文，解引用即 `CStr`，`as_ptr()` 可直投系统调用
    let sh = cs2!(c"/bin/sh");
    assert_eq!(&*sh, c"/bin/sh");
    // 字节串 / 字节数组：解引用即得原文 `[u8]`
    let b = b2!(b"abc");
    let c = b2!([0x61, 98, 99]);
    assert_eq!(&*b, &*c);
    // 整数：求值即得原文裸值，可直接算术、比较（空后缀视为 `i32`）
    let x = i2!(42u32);
    assert_eq!(x + 1, 43u32);
    // 浮点：求值即得原文裸值（空后缀视为 `f64`，`inf` / `NaN` 拒绝）
    let y = fl2!(3.15);
    assert_eq!(y.to_bits(), 3.15f64.to_bits());
    // 文件：路径相对被编译 crate 的 CARGO_MANIFEST_DIR，编译期读入
    let d = f2!("assets/fixture.bin");
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
| `i1!` / `i2!` / `i3!` | `42u8` / `-1` / `0xFFu16` 等整数字面量（空后缀视为 `i32`） | 低延迟 / 均衡 / 高强度 |
| `fl1!` / `fl2!` / `fl3!` | `3.15f32` / `-1.0` / `1e10` 等浮点字面量（空后缀视为 `f64`） | 低延迟 / 均衡 / 高强度 |
| `cs1!` / `cs2!` / `cs3!` | `"..."` / `c"..."` / `b"..."`（`b"..."` 可含非 UTF-8 字节，载荷禁内部 NUL） | 低延迟 / 均衡 / 高强度 |
| `f1!` / `f2!` / `f3!` | `"path/to/file"` 文件路径字面量 | 低延迟 / 均衡 / 高强度 |
| `s_fmt!` | `"...{}..."` 格式串 + 参数（2 档） | 字面量片段混淆后走 `format!`，返回 `String`（需 `std` / `alloc`） |

说明：

- 字符串宏展开为 `StackStr<N>` / `HeapStr<N>`，字节与文件宏展开为 `StackBytes<N>` / `HeapBytes<N>`，C 字符串宏展开为 `StackCStr<N>` / `HeapCStr<N>`（`N` 含结尾 `\0`，`N >= 1`；解引用为 `core::ffi::CStr`，`Drop` 自动清零），整数宏展开为对应裸整数值（`u8`/`i8`/`u16`/`i16`/`u32`/`i32`/`u64`/`i64`/`u128`/`i128`/`usize`/`isize`，由字面量后缀决定），浮点宏展开为对应裸浮点值（`f32` / `f64`，由字面量后缀决定）；返回的具体类型可能随编译变化，请使用类型推断，不要写死类型标注。
- 整数 / 浮点宏复用同一套字节混淆内核（整数小端编码、浮点按 `to_bits` 小端编码后走分块→加密→存储→发射）：载荷恒为单 chunk，可用存储形态仅 2 种，多态性靠原语叠加与发射形态维持；返回裸值，无 `Drop` 自动清零；`usize` / `isize` 按 64 位语义编码（`u64` / `i64` 中转后 `as` 转换）；浮点仅接受有限常规值（`inf` / `NaN` 一律拒绝），`-0.0` 按位保留符号位，断言请用 `to_bits()` 而非 `==`。
- C 字符串宏同样复用字节混淆内核：载荷追加结尾 `\0` 后整体混淆，运行时经 `try_from(&mut [u8])` 还原（首 NUL 截断 + 解密源擦除）；三种字面量形态语义等价，非 UTF-8 载荷请用 `b"..."`；载荷含任何内部 NUL 即编译期报错。
- 每次编译的混淆结果都不同（编译期随机），同一宏名的输出字节流不可复现。

## 适用场景 vs 不适用场景

**适合：**

- `no_std` 固件 / 裸机程序中隐藏字符串与常量字节。
- 需要规避静态字符串批量扫描的场景。

**不适合：**

- 需要合规审计、明文可读的场景。
- 超大文件混淆（展开体积随载荷与档位显著膨胀，见性能）。
- 需要制品哈希稳定（可复现构建）的发布流程。

## 平台与环境支持

- `no_std` 可用；`Heap*` 类型需启用 `alloc` feature。
- 支持操作系统：无平台相关代码（纯 Rust，主流桌面系统均可；裸机链路在 `x86_64-unknown-none` 上验证，见贡献章节）。
- Unsafe 代码：展开代码含 `unwrap_unchecked`（长度不变量已在展开期验证，运行时无校验开销）；容器 `Drop` 经 volatile 写清零明文。
- `fN!` 读取的文件需在编译时存在（路径相对被编译 crate 的 manifest 目录）。

## 特性标志 (Feature Flags)

| Feature | 默认启用 | 说明 |
| :--- | :--- | :--- |
| `default` | ✅ | `lib-unknown/alloc` + `obfstr2-macros/alloc`，开启 `Heap*` 堆内存类型 |
| `alloc`（各 crate 独立） | ❌ | 关闭时仅 `Stack*` 可用（纯栈、无堆，`no_std` 裸机可用） |

如需禁用默认特性（纯栈、无堆）：

```toml
[dependencies]
obfstr2 = { version = "0.1", default-features = false }
```

## 最小 Rust 版本 (MSRV)

MSRV 为 `1.98`，已在双 `Cargo.toml` 的 `rust-version` 声明。

## 性能 (Benchmarks)

以下数据的唯一来源是 `tests/perf.rs`（`cargo test --test perf -- --ignored --nocapture` 可复跑；报告-only，数字只展示不断言）：128B 全 `a` 同语义单宏程序，release 冷构建，guest 内循环 200 次解密求校验和（含进程启动开销）。多态导致每次结果不同，下表为单次实测示例，仅供量级参考。

| 用例                  | 编译耗时    | 运行耗时   | expand 字符数 | 产物二进制（未 strip） |
|:--------------------|:--------|:-------|:-----------|:---------------|
| 明文基线（`static` 直接引用） | 约 0.1s  | 约 11ms | 约 0.5k     | 约 447KB        |
| CasualX/obfstr 0.4  | 约 1.1s  | 约 11ms | 约 2.8k     | 约 449KB        |
| obfstr2（`b1!`）      | 约 2.2s  | 约 11ms | 约 31k      | 约 458KB        |
| obfstr2（`b2!`）      | 约 2.8s  | 约 11ms | 约 47k      | 约 470KB        |
| obfstr2（`b3!`）      | 约 2.4s  | 约 20ms | 约 55k      | 约 490KB        |


## 安全性 (Security)

如发现安全漏洞，请直接提交 Issue 说明（本仓库暂无私有上报通道）。

## 贡献 (Contributing)

欢迎提交 Issue 和 Pull Request！

- 本地验证（分层，增量缓存下约 15 秒）：
  - `cargo test --test smoke --test s_fmt`：全部宏正确性，进程内断言，毫秒级；
  - `cargo test --test compile_fail`：非法输入的编译期拒绝（各用例隔离的 dyntest 工程）；
  - `cargo test --test nostd`：`x86_64-unknown-none` 裸机链路（`b1` 纯栈无分配 + `b2` 含堆，需安装该 target）；
  - `cargo test --test perf -- --ignored --nocapture`：性能对比报告（明文基线 vs CasualX vs `b1/b2/b3`，编译耗时 / 运行耗时 / expand 字符数 / 产物体积，只展示不断言，需联网拉取 `obfstr` 并安装 `cargo-expand`）；
  - `cd obfstr2-macros && cargo test --lib`：纯单元测试（格式串切分、多态展开，毫秒级）。
- 提交 PR 前请先阅读[设计哲学](#设计哲学-design-philosophy)：新增混淆原语请以 `Crypto` / `Storage` 表项形式接入（分别位于 `obfstr2-macros/src/crypto.rs` 与 `storage.rs`），编排层（`core.rs::build_obfuscated_bytes`）保持不动；新增宏需在 `obfstr2/src/lib.rs` 加重导出 + 用户文档，`obfstr2-macros` 侧只留一句话指针。

## 变更日志 (Changelog)

版本变更详情请见 [CHANGELOG.md](CHANGELOG.md)。

## 开源协议 (License)

[MIT License](./LICENSE)
