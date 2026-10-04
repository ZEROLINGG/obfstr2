//! `obfstr2` 的过程宏实现 crate：字符串 / 字节 / 文件 / 整数 / 浮点编译期混淆入口。
//!
//! 对外暴露 `s1~3!`、`b1~3!`、`f1~3!`、`i1~3!`、`fl1~3!`（低延迟 / 均衡 / 高强度三档）与 `s_fmt!`；
//! 具体行为见各宏文档，通过 `obfstr2` 根 crate 转发（`pub use obfstr2_macros::*`）。
mod bytes;
mod combine;
mod core;
mod crypto;
mod float;
mod int;
mod storage;
mod str;

use proc_macro::TokenStream;

fn expand_str(input: TokenStream, build: fn(String) -> proc_macro2::TokenStream) -> TokenStream {
    match syn::parse::<syn::LitStr>(input) {
        Ok(lit) => build(lit.value()).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_bytes(input: TokenStream, build: fn(Vec<u8>) -> proc_macro2::TokenStream) -> TokenStream {
    // 1. b"..." 字节串形式
    if let Ok(lit) = syn::parse::<syn::LitByteStr>(input.clone()) {
        return build(lit.value()).into();
    }
    // 2. [0x41, 66, ...] 字节数组形式（元素必须为 0..=255 的整数字面量）
    match syn::parse::<syn::ExprArray>(input) {
        Ok(arr) => {
            let mut bytes = Vec::with_capacity(arr.elems.len());
            for elem in &arr.elems {
                match elem {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(n),
                        ..
                    }) => match n.base10_parse::<u8>() {
                        Ok(b) => bytes.push(b),
                        Err(_) => {
                            return syn::Error::new_spanned(n, "字节数组元素必须在 0..=255 范围内")
                                .to_compile_error()
                                .into();
                        }
                    },
                    other => {
                        return syn::Error::new_spanned(
                            other,
                            "字节数组只接受 0..=255 的整数字面量",
                        )
                        .to_compile_error()
                        .into();
                    }
                }
            }
            build(bytes).into()
        }
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_int(
    input: TokenStream,
    build: fn(int::ParsedInt) -> proc_macro2::TokenStream,
) -> TokenStream {
    match int::parse_int(input.into()) {
        Ok(parsed) => build(parsed).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_float(
    input: TokenStream,
    build: fn(float::ParsedFloat) -> proc_macro2::TokenStream,
) -> TokenStream {
    match float::parse_float(input.into()) {
        Ok(parsed) => build(parsed).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_file(input: TokenStream, build: fn(Vec<u8>) -> proc_macro2::TokenStream) -> TokenStream {
    let path_lit = match syn::parse::<syn::LitStr>(input) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    // 路径相对于被编译 crate 的 CARGO_MANIFEST_DIR 解析（与 include_bytes! 一致）
    let rel = path_lit.value();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let full = std::path::Path::new(&manifest_dir).join(&rel);
    let data = match std::fs::read(&full) {
        Ok(d) => d,
        Err(e) => {
            return syn::Error::new(
                path_lit.span(),
                format!("无法读取文件 {}: {e}", full.display()),
            )
            .to_compile_error()
            .into();
        }
    };
    build(data).into()
}

/// 字符串混淆宏（低延迟档，对应 `s1`）。
///
/// 只接受字符串字面量 `"..."`，展开为求值即得原文的表达式（类型为
/// `StackStr<N>`，请使用类型推断，不要写死类型标注）。
/// # Examples
///
/// ```rust,ignore
/// // 过程宏无法在定义 crate 内 doctest（需外部调用方展开）；
/// // 覆盖见根 crate `tests/smoke.rs`（s1 同理）。
/// use obfstr2::s1;
/// let s = s1!("hello");
/// ```
#[proc_macro]
pub fn s1(input: TokenStream) -> TokenStream {
    expand_str(input, str::s1)
}

/// 字符串混淆宏（均衡档，对应 `s2`）。
///
/// 只接受字符串字面量 `"..."`。返回的具体字符串类型（`StackStr` /
/// `HeapStr`）同一宏名下可能随编译变化，请使用类型推断。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`。
/// use obfstr2::s2;
/// let s = s2!("hello");
/// ```
#[proc_macro]
pub fn s2(input: TokenStream) -> TokenStream {
    expand_str(input, str::s2)
}

/// 字符串混淆宏（高强度档，对应 `s3`）。
///
/// 只接受字符串字面量 `"..."`，展开类型规则同 [`s2`](s2())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（s3 同理）。
/// use obfstr2::s3;
/// let s = s3!("hello");
/// ```
#[proc_macro]
pub fn s3(input: TokenStream) -> TokenStream {
    expand_str(input, str::s3)
}

/// 字节串混淆宏（低延迟档，对应 `b1`）。
///
/// 接受字节串字面量 `b"..."` 或字节数组 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量），展开为求值即得原文的字节容器表达式
/// （`StackBytes<N>` / `HeapBytes<N>`，可解引用为 `[u8]`）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（b1 同理）。
/// use obfstr2::b1;
/// let b = b1!(b"abc");
/// ```
#[proc_macro]
pub fn b1(input: TokenStream) -> TokenStream {
    expand_bytes(input, bytes::b1)
}

/// 字节串混淆宏（均衡档，对应 `b2`）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`。
/// use obfstr2::b2;
/// let b = b2!([0x61, 98, 99]);
/// ```
#[proc_macro]
pub fn b2(input: TokenStream) -> TokenStream {
    expand_bytes(input, bytes::b2)
}

/// 字节串混淆宏（高强度档，对应 `b3`）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（b3 同理）。
/// use obfstr2::b3;
/// let b = b3!(b"abc");
/// ```
#[proc_macro]
pub fn b3(input: TokenStream) -> TokenStream {
    expand_bytes(input, bytes::b3)
}

/// 文件混淆宏（低延迟档，对应 `b1`）。
///
/// 接受文件路径字面量（如 `"assets/fixture.bin"`，相对于被编译 crate 的
/// `CARGO_MANIFEST_DIR` 解析），编译期读入文件内容并混淆，展开为求值即得
/// 文件原文的字节容器表达式（`StackBytes<N>` / `HeapBytes<N>`）。
/// 需自行保证文件存在；文件缺失或不可读时报编译错误。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（f1 同理）。
/// use obfstr2::f1;
/// let b = f1!("assets/fixture.bin");
/// ```
#[proc_macro]
pub fn f1(input: TokenStream) -> TokenStream {
    expand_file(input, bytes::b1)
}

/// 文件混淆宏（均衡档，对应 `b2`）。
///
/// 输入与展开规则同 [`f1`](f1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`。
/// use obfstr2::f2;
/// let b = f2!("assets/fixture.bin");
/// ```
#[proc_macro]
pub fn f2(input: TokenStream) -> TokenStream {
    expand_file(input, bytes::b2)
}

/// 文件混淆宏（高强度档，对应 `b3`）。
///
/// 输入与展开规则同 [`f1`](f1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（f3 同理）。
/// use obfstr2::f3;
/// let b = f3!("assets/fixture.bin");
/// ```
#[proc_macro]
pub fn f3(input: TokenStream) -> TokenStream {
    expand_file(input, bytes::b3)
}

/// 格式化字符串混淆宏（2 档，对应 `s2`）。
///
/// 首参须为字符串字面量：其中的字面量片段逐个混淆后注入 `format!` 调用，
/// 占位符与后续参数原样保留。返回 `String`，需要调用方有 `std` / `alloc`。
///
/// # Examples
///
/// ```rust,ignore
/// // 同 s2：不可 doctest，覆盖见根 crate `tests/s_fmt.rs`。
/// use obfstr2::s_fmt;
/// let s = s_fmt!("hello {}", name);
/// ```
#[proc_macro]
pub fn s_fmt(input: TokenStream) -> TokenStream {
    combine::sfmt(input.into()).into()
}

/// 整数混淆宏（低延迟档，对应 `i1`）。
///
/// 只接受整数字面量（如 `42u8`、`-1`、`0xFFu16`，空后缀视为 `i32`），
/// 展开为求值即得原文的裸整数表达式，可直接算术、比较、`let` 绑定传递。
/// 注意：返回裸值，无 `Drop` 自动清零（与 `StackStr` 不同）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（i1 同理）。
/// use obfstr2::i1;
/// let x = i1!(42u8);
/// ```
#[proc_macro]
pub fn i1(input: TokenStream) -> TokenStream {
    expand_int(input, int::i1)
}

/// 整数混淆宏（均衡档，对应 `i2`）。
///
/// 输入与展开规则同 [`i1`](i1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`。
/// use obfstr2::i2;
/// let x = i2!(-1);
/// ```
#[proc_macro]
pub fn i2(input: TokenStream) -> TokenStream {
    expand_int(input, int::i2)
}

/// 整数混淆宏（高强度档，对应 `i3`）。
///
/// 输入与展开规则同 [`i1`](i1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（i3 同理）。
/// use obfstr2::i3;
/// let x = i3!(0xFFu16);
/// ```
#[proc_macro]
pub fn i3(input: TokenStream) -> TokenStream {
    expand_int(input, int::i3)
}

/// 浮点混淆宏（低延迟档，对应 `fl1`）。
///
/// 只接受浮点字面量（如 `3.14f32`、`-1.0`、`1e10`，空后缀视为 `f64`），
/// 展开为求值即得原文的裸浮点表达式，可直接算术、比较、`let` 绑定传递。
/// 仅接受有限常规值：`inf` / `NaN` 一律拒绝；`-0.0` 按位保留符号位。
/// 注意：返回裸值，无 `Drop` 自动清零（与 `StackStr` 不同）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（fl1 同理）。
/// use obfstr2::fl1;
/// let x = fl1!(1.5f32);
/// ```
#[proc_macro]
pub fn fl1(input: TokenStream) -> TokenStream {
    expand_float(input, float::fl1)
}

/// 浮点混淆宏（均衡档，对应 `fl2`）。
///
/// 输入与展开规则同 [`fl1`](fl1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`。
/// use obfstr2::fl2;
/// let x = fl2!(3.15);
/// ```
#[proc_macro]
pub fn fl2(input: TokenStream) -> TokenStream {
    expand_float(input, float::fl2)
}

/// 浮点混淆宏（高强度档，对应 `fl3`）。
///
/// 输入与展开规则同 [`fl1`](fl1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见根 crate `tests/smoke.rs`（fl3 同理）。
/// use obfstr2::fl3;
/// let x = fl3!(-0.0);
/// ```
#[proc_macro]
pub fn fl3(input: TokenStream) -> TokenStream {
    expand_float(input, float::fl3)
}
