#![doc = include_str!("../README.md")]
#![no_std]
pub use lib_unknown::crypto;
pub use lib_unknown::types;

/// 字符串混淆宏（低延迟档，对应 `s1`）。
///
/// 只接受字符串字面量 `"..."`，展开为求值即得原文的表达式（类型为
/// `StackStr<N>`，请使用类型推断，不要写死类型标注）。
///
/// 用法：`let s = s1!("hello");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::s1;

/// 字符串混淆宏（均衡档，对应 `s2`）。
///
/// 只接受字符串字面量 `"..."`。返回的具体字符串类型（`StackStr` /
/// `HeapStr`）同一宏名下可能随编译变化，请使用类型推断。
///
/// 用法：`let s = s2!("hello");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::s2;

/// 字符串混淆宏（高强度档，对应 `s3`）。
///
/// 只接受字符串字面量 `"..."`，展开类型规则同 [`s2`](s2!())。
///
/// 用法：`let s = s3!("hello");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::s3;

/// 字节串混淆宏（低延迟档，对应 `b1`）。
///
/// 接受字节串字面量 `b"..."` 或字节数组 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量），展开为求值即得原文的字节容器表达式
/// （`StackBytes<N>` / `HeapBytes<N>`，可解引用为 `[u8]`）。
///
/// 用法：`let b = b1!(b"abc");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::b1;

/// 字节串混淆宏（均衡档，对应 `b2`）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
///
/// 用法：`let b = b2!([0x61, 98, 99]);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::b2;

/// 字节串混淆宏（高强度档，对应 `b3`）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
///
/// 用法：`let b = b3!(b"abc");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::b3;

/// 文件混淆宏（低延迟档，对应 `b1`）。
///
/// 接受文件路径字面量（如 `"assets/fixture.bin"`，相对于被编译 crate 的
/// `CARGO_MANIFEST_DIR` 解析），编译期读入文件内容并混淆，展开为求值即得
/// 文件原文的字节容器表达式（`StackBytes<N>` / `HeapBytes<N>`）。
/// 需自行保证文件存在；文件缺失或不可读时报编译错误。
///
/// 用法：`let b = f1!("assets/fixture.bin");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::f1;

/// 文件混淆宏（均衡档，对应 `b2`）。
///
/// 输入与展开规则同 [`f1`](f1!())。
///
/// 用法：`let b = f2!("assets/fixture.bin");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::f2;

/// 文件混淆宏（高强度档，对应 `b3`）。
///
/// 输入与展开规则同 [`f1`](f1!())。
///
/// 用法：`let b = f3!("assets/fixture.bin");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::f3;

/// 格式化字符串混淆宏（2 档，对应 `s2`）。
///
/// 首参须为字符串字面量：其中的字面量片段逐个混淆后注入 `format!` 调用，
/// 占位符与后续参数原样保留。返回 `String`，需要调用方有 `std` / `alloc`。
///
/// 用法：`let s = s_fmt!("hello {}", name);`。过程宏不可 doctest，覆盖见 `tests/s_fmt.rs`。
pub use obfstr2_macros::s_fmt;

/// 整数混淆宏（低延迟档，对应 `i1`）。
///
/// 只接受整数字面量（如 `42u8`、`-1`、`0xFFu16`，空后缀视为 `i32`），
/// 展开为求值即得原文的裸整数表达式，可直接算术、比较、`let` 绑定传递。
/// 注意：返回裸值，无 `Drop` 自动清零（与 `StackStr` 不同）。
///
/// 用法：`let x = i1!(42u8);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::i1;

/// 整数混淆宏（均衡档，对应 `i2`）。
///
/// 输入与展开规则同 [`i1`](i1!())。
///
/// 用法：`let x = i2!(-1);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::i2;

/// 整数混淆宏（高强度档，对应 `i3`）。
///
/// 输入与展开规则同 [`i1`](i1!())。
///
/// 用法：`let x = i3!(0xFFu16);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::i3;

/// 浮点混淆宏（低延迟档，对应 `fl1`）。
///
/// 只接受浮点字面量（如 `3.14f32`、`-1.0`、`1e10`，空后缀视为 `f64`），
/// 展开为求值即得原文的裸浮点表达式，可直接算术、比较、`let` 绑定传递。
/// 仅接受有限常规值：`inf` / `NaN` 一律拒绝；`-0.0` 按位保留符号位。
/// 注意：返回裸值，无 `Drop` 自动清零（与 `StackStr` 不同）。
///
/// 用法：`let x = fl1!(1.5f32);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::fl1;

/// 浮点混淆宏（均衡档，对应 `fl2`）。
///
/// 输入与展开规则同 [`fl1`](fl1!())。
///
/// 用法：`let x = fl2!(3.15);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::fl2;

/// 浮点混淆宏（高强度档，对应 `fl3`）。
///
/// 输入与展开规则同 [`fl1`](fl1!())。
///
/// 用法：`let x = fl3!(-0.0);`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::fl3;

/// C 字符串混淆宏（低延迟档，对应 `cs1`）。
///
/// 接受字符串字面量 `"..."`、C 字符串字面量 `c"..."` 或字节串字面量
/// `b"..."`（后者可表达非 UTF-8 载荷；三者语义等价，`b"..."` 不校验 UTF-8）。
/// 载荷不能包含内部 NUL（宏会追加唯一的结尾 `\0`）。
/// 展开为求值即得原文的 C 字符串容器表达式（`StackCStr<N>`，`N` 含结尾 `\0`，
/// 请使用类型推断），可解引用为 `core::ffi::CStr`、`as_ptr()` 直投系统调用，
/// `Drop` 时自动清零。
///
/// 用法：`let s = cs1!(c"/bin/sh");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::cs1;

/// C 字符串混淆宏（均衡档，对应 `cs2`）。
///
/// 输入与展开规则同 [`cs1`](cs1!())；返回的具体容器类型（`StackCStr` /
/// `HeapCStr`）同一宏名下可能随编译变化，请使用类型推断。
///
/// 用法：`let s = cs2!("/bin/sh");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::cs2;

/// C 字符串混淆宏（高强度档，对应 `cs3`）。
///
/// 输入与展开规则同 [`cs1`](cs1!())。
///
/// 用法：`let s = cs3!(b"/bin/sh");`。过程宏不可 doctest，覆盖见 `tests/smoke.rs`。
pub use obfstr2_macros::cs3;
