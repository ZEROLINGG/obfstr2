//! `obfstr2` 的内部过程宏实现 crate，无运行时，不可 doctest。
//!
//! 对外暴露 `s1~3!`、`b1~3!`、`f1~3!`、`i1~3!`、`fl1~3!`、`cs1~3!`（低延迟 / 均衡 / 高强度三档）与 `s_fmt!` 的过程宏本体。
//!
//! # Warning
//!
//! 本 crate 文档仅面向实现者，用户请直接依赖 `obfstr2`，使用根 crate 同名宏（`macro_rules` 包装）并以其文档与可运行示例为准。
mod combine;
mod core;
mod crypto;
mod parse;
mod storage;
mod types;

use proc_macro::TokenStream;

fn err_to_compile_error(span: proc_macro2::Span, msg: String) -> TokenStream {
    syn::Error::new(span, msg).to_compile_error().into()
}

fn expand_str(
    input: TokenStream,
    build: fn(String) -> Result<proc_macro2::TokenStream, String>,
) -> TokenStream {
    match parse::parse_str(input.into()) {
        Ok(s) => match build(s) {
            Ok(ts) => ts.into(),
            Err(e) => err_to_compile_error(proc_macro2::Span::call_site(), e),
        },
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_bytes(
    input: TokenStream,
    build: fn(Vec<u8>) -> Result<proc_macro2::TokenStream, String>,
) -> TokenStream {
    match parse::parse_bytes(input.into()) {
        Ok(bytes) => match build(bytes) {
            Ok(ts) => ts.into(),
            Err(e) => err_to_compile_error(proc_macro2::Span::call_site(), e),
        },
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_int(
    input: TokenStream,
    build: fn(parse::ParsedInt) -> Result<proc_macro2::TokenStream, String>,
) -> TokenStream {
    match parse::parse_int(input.into()) {
        Ok(parsed) => match build(parsed) {
            Ok(ts) => ts.into(),
            Err(e) => err_to_compile_error(proc_macro2::Span::call_site(), e),
        },
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_float(
    input: TokenStream,
    build: fn(parse::ParsedFloat) -> Result<proc_macro2::TokenStream, String>,
) -> TokenStream {
    match parse::parse_float(input.into()) {
        Ok(parsed) => match build(parsed) {
            Ok(ts) => ts.into(),
            Err(e) => err_to_compile_error(proc_macro2::Span::call_site(), e),
        },
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_cstr(
    input: TokenStream,
    build: fn(Vec<u8>) -> Result<proc_macro2::TokenStream, String>,
) -> TokenStream {
    match parse::parse_cstr(input.into()) {
        Ok(payload) => match build(payload) {
            Ok(ts) => ts.into(),
            Err(e) => err_to_compile_error(proc_macro2::Span::call_site(), e),
        },
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_file(
    input: TokenStream,
    build: fn(Vec<u8>) -> Result<proc_macro2::TokenStream, String>,
) -> TokenStream {
    match parse::parse_file(input.into()) {
        Ok(data) => match build(data) {
            Ok(ts) => ts.into(),
            Err(e) => err_to_compile_error(proc_macro2::Span::call_site(), e),
        },
        Err(e) => e.to_compile_error().into(),
    }
}
/// 字符串混淆宏本体（低延迟档）：只接受字符串字面量 `"..."`，展开为求值即得原文的表达式。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn s1(input: TokenStream) -> TokenStream {
    expand_str(input, types::s1)
}

/// 字符串混淆宏本体（均衡档）：只接受字符串字面量 `"..."`；返回的具体字符串类型（`StackStr` /
/// `HeapStr`）同一宏名下可能随编译变化。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn s2(input: TokenStream) -> TokenStream {
    expand_str(input, types::s2)
}

/// 字符串混淆宏本体（高强度档）：只接受字符串字面量 `"..."`，展开类型规则同 `s2`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn s3(input: TokenStream) -> TokenStream {
    expand_str(input, types::s3)
}

/// 字节串混淆宏本体（低延迟档）：接受字节串字面量 `b"..."` 或字节数组 `[0x41, 66, ...]`
/// （元素须为 0..=255 的整数字面量），展开为求值即得原文的字节容器表达式。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn b1(input: TokenStream) -> TokenStream {
    expand_bytes(input, types::b1)
}

/// 字节串混淆宏本体（均衡档）：接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn b2(input: TokenStream) -> TokenStream {
    expand_bytes(input, types::b2)
}

/// 字节串混淆宏本体（高强度档）：接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn b3(input: TokenStream) -> TokenStream {
    expand_bytes(input, types::b3)
}

/// 文件混淆宏本体（低延迟档）：接受文件路径字面量（相对于被编译 crate 的
/// `CARGO_MANIFEST_DIR` 解析），编译期读入文件内容并混淆；文件缺失或不可读时报编译错误。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn f1(input: TokenStream) -> TokenStream {
    expand_file(input, types::b1)
}

/// 文件混淆宏本体（均衡档）：输入与展开规则同 `f1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn f2(input: TokenStream) -> TokenStream {
    expand_file(input, types::b2)
}

/// 文件混淆宏本体（高强度档）：输入与展开规则同 `f1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn f3(input: TokenStream) -> TokenStream {
    expand_file(input, types::b3)
}

/// 格式化字符串混淆宏本体（1 档）：首参须为字符串字面量，其中的字面量片段逐个混淆后注入 `format!` 调用，
/// 占位符与后续参数原样保留。返回 `String`，需要调用方有 `std` / `alloc`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/s_fmt.rs`。
#[proc_macro]
pub fn s_fmt(input: TokenStream) -> TokenStream {
    combine::sfmt(input.into()).into()
}

/// 整数混淆宏本体（低延迟档）：只接受整数字面量（如 `42u8`、`-1`、`0xFFu16`，空后缀视为 `i32`），
/// 展开为求值即得原文的裸整数表达式；返回裸值，无 `Drop` 自动清零。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn i1(input: TokenStream) -> TokenStream {
    expand_int(input, types::i1)
}

/// 整数混淆宏本体（均衡档）：输入与展开规则同 `i1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn i2(input: TokenStream) -> TokenStream {
    expand_int(input, types::i2)
}

/// 整数混淆宏本体（高强度档）：输入与展开规则同 `i1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn i3(input: TokenStream) -> TokenStream {
    expand_int(input, types::i3)
}

/// 浮点混淆宏本体（低延迟档）：只接受浮点字面量（如 `3.14f32`、`-1.0`、`1e10`，空后缀视为 `f64`），
/// 展开为求值即得原文的裸浮点表达式；仅接受有限常规值，`-0.0` 按位保留符号位；返回裸值，无 `Drop` 自动清零。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn fl1(input: TokenStream) -> TokenStream {
    expand_float(input, types::fl1)
}

/// 浮点混淆宏本体（均衡档）：输入与展开规则同 `fl1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn fl2(input: TokenStream) -> TokenStream {
    expand_float(input, types::fl2)
}

/// 浮点混淆宏本体（高强度档）：输入与展开规则同 `fl1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn fl3(input: TokenStream) -> TokenStream {
    expand_float(input, types::fl3)
}

/// C 字符串混淆宏本体（低延迟档）：接受 `"..."` / `c"..."` / `b"..."` 三种字面量（语义等价，
/// `b"..."` 可表达非 UTF-8 载荷）；载荷禁内部 NUL，宏追加唯一的结尾 `\0`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn cs1(input: TokenStream) -> TokenStream {
    expand_cstr(input, types::cs1)
}

/// C 字符串混淆宏本体（均衡档）：输入与展开规则同 `cs1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn cs2(input: TokenStream) -> TokenStream {
    expand_cstr(input, types::cs2)
}
/// C 字符串混淆宏本体（高强度档）：输入与展开规则同 `cs1`。
///
/// # Warning
///
/// 内部实现，外部请使用 `obfstr2` 根 crate 的同名宏；宏本体与展开形态可随版本变更，不做稳定性承诺。
/// 用户文档与可运行示例见 `obfstr2` 根 crate，覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn cs3(input: TokenStream) -> TokenStream {
    expand_cstr(input, types::cs3)
}
